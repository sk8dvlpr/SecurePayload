package main

import (
	"context"
	"log"
	"sync"
	"time"
)

// ReplayStore adalah kontrak replay guard: Claim mengembalikan true jika kunci
// belum pernah terlihat (klaim berhasil) dan false jika merupakan replay.
// Kontrak identik dengan tipe securepayload.ReplayStore pada go-sdk.
type ReplayStore interface {
	Claim(cacheKey string, ttl int) bool
}

// memoryReplayStore adalah replay store in-process berbasis TTL.
//
// CATATAN OPERASIONAL: store ini hanya valid untuk satu instance service.
// Untuk multi-replika, gunakan store bersama (mis. Redis) — lihat README.md.
type memoryReplayStore struct {
	mu         sync.Mutex
	m          map[string]time.Time
	max        int // batas entri; penuh → tolak klaim (fail-closed)
	denyLogged bool
}

func newMemoryReplayStore(maxEntries int) *memoryReplayStore {
	return &memoryReplayStore{m: make(map[string]time.Time), max: maxEntries}
}

// Claim mencatat cacheKey hingga now+ttl dan melaporkan apakah klaim pertama.
func (s *memoryReplayStore) Claim(cacheKey string, ttl int) bool {
	now := time.Now()
	exp := now.Add(time.Duration(ttl) * time.Second)

	s.mu.Lock()
	defer s.mu.Unlock()

	if t, ok := s.m[cacheKey]; ok && now.Before(t) {
		return false // sudah diklaim dan belum kedaluwarsa → replay
	}

	if len(s.m) >= s.max {
		s.purgeLocked(now)
		if len(s.m) >= s.max {
			// Store penuh setelah purge → gagal tertutup daripada membiarkan
			// nonce lolos tanpa perlindungan replay.
			if !s.denyLogged {
				log.Printf("replay store penuh (%d entri); klaim ditolak fail-closed", s.max)
				s.denyLogged = true
			}
			return false
		}
	}
	s.m[cacheKey] = exp
	return true
}

// purgeLocked menghapus entri kedaluwarsa. Harus dipanggil dengan lock aktif.
func (s *memoryReplayStore) purgeLocked(now time.Time) {
	for k, t := range s.m {
		if !now.Before(t) {
			delete(s.m, k)
		}
	}
}

// janitor membersihkan entri kedaluwarsa secara berkala hingga ctx selesai.
func (s *memoryReplayStore) janitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			s.purgeLocked(now)
			s.mu.Unlock()
		}
	}
}
