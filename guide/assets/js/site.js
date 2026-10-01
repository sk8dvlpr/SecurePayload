/**
 * SecurePayload User Guide — client interactions (vanilla JS, no runtime deps).
 */
(function () {
  "use strict";

  var STORAGE_THEME = "sp-guide-theme";
  var STORAGE_LANG = "sp-guide-lang";
  var STORAGE_CHECKLIST = "sp-guide-checklist";
  var STORAGE_TABS = "sp-guide-tabs";

  var root = document.documentElement;
  var body = document.body;

  function safeStorage(kind) {
    try {
      var s = kind === "session" ? sessionStorage : localStorage;
      var k = "__sp_test__";
      s.setItem(k, "1");
      s.removeItem(k);
      return s;
    } catch (e) {
      return null;
    }
  }

  var local = safeStorage("local");
  var session = safeStorage("session");

  /** Directory that contains id/, en/, and assets/. */
  function siteRoot() {
    var path = window.location.pathname;
    var m = path.match(/^(.*)\/(?:id|en)(?:\/|$)/);
    if (m) {
      return (m[1] || "") + "/";
    }
    if (/\/(?:index|404)\.html$/i.test(path)) {
      return path.replace(/\/[^/]*$/, "/");
    }
    if (path.endsWith("/")) return path;
    return path.replace(/\/[^/]*$/, "/") || "/";
  }

  function guideUrl(rel) {
    rel = String(rel || "").replace(/^\/+/, "");
    return siteRoot() + rel;
  }

  function assetUrl(relative) {
    var base = document.querySelector("meta[name='sp-asset-base']");
    if (base && base.getAttribute("content")) {
      var b = base.getAttribute("content");
      return b.replace(/\/?$/, "/") + relative.replace(/^\//, "");
    }
    return siteRoot() + "assets/" + relative.replace(/^\/?assets\//, "");
  }

  function currentLang() {
    var lang = (root.getAttribute("lang") || "id").slice(0, 2).toLowerCase();
    var m = window.location.pathname.match(/\/(id|en)(?:\/|$)/);
    if (m) lang = m[1];
    return lang === "en" ? "en" : "id";
  }

  function siblingLangPath(targetLang) {
    var path = window.location.pathname;
    var hash = window.location.hash || "";
    var search = window.location.search || "";
    var m = path.match(/^(.*)\/(id|en)(\/.*)?$/);
    if (m) {
      var rest = m[3] || "/index.html";
      if (rest === "/") rest = "/index.html";
      return m[1] + "/" + targetLang + rest + search + hash;
    }
    return siteRoot() + targetLang + "/index.html" + search + hash;
  }

  /** /id (no trailing slash) makes relative links resolve to /basics.html */

  /** Resolve in-page relative hrefs against the lang directory (fixes /id without slash). */
  function fixRelativeNavLinks() {
    var path = window.location.pathname;
    var m = path.match(/^(.*)\/(id|en)(?:\/(.*))?$/);
    if (!m) return;
    var langBase = m[1] + '/' + m[2] + '/';
    var rest = m[3] || '';
    var dirUrl;
    if (!rest || rest === '' || rest.indexOf('/') === -1 && !/\.html?$/i.test(rest)) {
      dirUrl = langBase;
    } else if (rest.endsWith('/')) {
      dirUrl = langBase + rest;
    } else {
      dirUrl = langBase + rest.replace(/[^/]*$/, '');
    }
    var origin = window.location.origin || 'http://local.invalid';
    document.querySelectorAll('a[href]').forEach(function (a) {
      if (a.hasAttribute('data-lang-switch')) return;
      var href = a.getAttribute('href');
      if (!href || /^(https?:|mailto:|javascript:|#|\/\/)/i.test(href)) return;
      if (href.charAt(0) === '/') return;
      try {
        var abs = new URL(href, origin + dirUrl);
        var next = abs.pathname + abs.search + abs.hash;
        if (next !== href) a.setAttribute('href', next);
      } catch (err) {
        /* ignore */
      }
    });
  }

  /** Do not redirect /id/ <-> /id/index.html (causes refresh loops on many static servers). */
  function ensureLangTrailingSlash() {
    return false;
  }

  /* —— Theme —— */
  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    var btns = document.querySelectorAll("[data-theme-set]");
    btns.forEach(function (btn) {
      btn.setAttribute("aria-pressed", btn.getAttribute("data-theme-set") === theme ? "true" : "false");
    });
    if (local) local.setItem(STORAGE_THEME, theme);
  }

  function initTheme() {
    var saved = local && local.getItem(STORAGE_THEME);
    var initial = saved || root.getAttribute("data-theme") || "auto";
    if (["light", "dark", "auto"].indexOf(initial) === -1) initial = "auto";
    applyTheme(initial);
    document.querySelectorAll("[data-theme-set]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        applyTheme(btn.getAttribute("data-theme-set"));
      });
    });
  }

  /* —— Language —— */
  function initLang() {
    var lang = currentLang();
    document.querySelectorAll("[data-lang-set]").forEach(function (btn) {
      var code = btn.getAttribute("data-lang-set");
      btn.setAttribute("aria-pressed", code === lang ? "true" : "false");
      btn.addEventListener("click", function (e) {
        if (btn.tagName === "A") return;
        e.preventDefault();
        var target = btn.getAttribute("data-lang-set");
        if (target === lang) return;
        if (local) local.setItem(STORAGE_LANG, target);
        window.location.href = siblingLangPath(target);
      });
    });
    document.querySelectorAll("a[data-lang-switch]").forEach(function (link) {
      link.setAttribute("href", siblingLangPath(link.getAttribute("data-lang-switch")));
    });
    var saved = local && local.getItem(STORAGE_LANG);
    if (saved && !sessionStorage.getItem("sp-lang-hint-shown")) {
      try { sessionStorage.setItem("sp-lang-hint-shown", "1"); } catch (err) { /* ignore */ }
    }
  }

  /* —— Sidebar drawer —— */
  function setSidebar(open) {
    body.classList.toggle("sidebar-open", open);
    var toggle = document.querySelector("[data-sidebar-toggle]");
    if (toggle) toggle.setAttribute("aria-expanded", open ? "true" : "false");
    var sidebar = document.querySelector(".site-sidebar");
    if (sidebar) sidebar.setAttribute("aria-hidden", open ? "false" : "true");
  }

  function initSidebar() {
    var toggle = document.querySelector("[data-sidebar-toggle]");
    var backdrop = document.querySelector(".sidebar-backdrop");
    if (toggle) {
      toggle.addEventListener("click", function () {
        setSidebar(!body.classList.contains("sidebar-open"));
      });
    }
    if (backdrop) {
      backdrop.addEventListener("click", function () { setSidebar(false); });
    }
    document.querySelectorAll(".site-sidebar a").forEach(function (a) {
      a.addEventListener("click", function () {
        if (window.matchMedia("(max-width: 1023px)").matches) setSidebar(false);
      });
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && body.classList.contains("sidebar-open")) {
        setSidebar(false);
        if (toggle) toggle.focus();
      }
    });
    if (window.matchMedia("(min-width: 1024px)").matches) {
      var sidebar = document.querySelector(".site-sidebar");
      if (sidebar) sidebar.removeAttribute("aria-hidden");
    }
  }

  /* —— Tabs —— */
  function activateTab(tab) {
    var list = tab.closest('[role="tablist"]');
    if (!list) return;
    var tabs = list.querySelectorAll('[role="tab"]');
    tabs.forEach(function (t) {
      var on = t === tab;
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
      var panelId = t.getAttribute("aria-controls");
      var panel = panelId && document.getElementById(panelId);
      if (panel) panel.hidden = !on;
    });
    var groupId = list.getAttribute("data-tabs-id");
    if (groupId && session) {
      session.setItem(STORAGE_TABS + ":" + groupId, tab.id || tab.textContent.trim());
    }
  }

  function initTabs() {
    document.querySelectorAll('[role="tablist"]').forEach(function (list) {
      var tabs = list.querySelectorAll('[role="tab"]');
      var groupId = list.getAttribute("data-tabs-id");
      if (groupId && session) {
        var saved = session.getItem(STORAGE_TABS + ":" + groupId);
        if (saved) {
          tabs.forEach(function (t) {
            if (t.id === saved || t.textContent.trim() === saved) activateTab(t);
          });
        }
      }
      tabs.forEach(function (tab, i) {
        if (!tab.hasAttribute("tabindex")) tab.tabIndex = tab.getAttribute("aria-selected") === "true" ? 0 : -1;
        tab.addEventListener("click", function () { activateTab(tab); });
        tab.addEventListener("keydown", function (e) {
          var idx = Array.prototype.indexOf.call(tabs, tab);
          if (e.key === "ArrowRight") { e.preventDefault(); activateTab(tabs[(idx + 1) % tabs.length]); tabs[(idx + 1) % tabs.length].focus(); }
          if (e.key === "ArrowLeft") { e.preventDefault(); activateTab(tabs[(idx - 1 + tabs.length) % tabs.length]); tabs[(idx - 1 + tabs.length) % tabs.length].focus(); }
        });
        if (i === 0 && tab.getAttribute("aria-selected") !== "true") {
          /* keep build markup defaults */
        }
      });
    });
  }

  /* —— Copy code —— */
  function initCopyCode() {
    document.querySelectorAll(".code").forEach(function (block) {
      var btn = block.querySelector("[data-copy], .copy");
      var pre = block.querySelector("pre");
      if (!btn || !pre) return;
      var defaultLabel = btn.textContent.trim() || "Copy";
      btn.addEventListener("click", function () {
        var text = pre.textContent;
        function done() {
          btn.textContent = root.lang === "en" ? "Copied ✓" : "Tersalin ✓";
          setTimeout(function () { btn.textContent = defaultLabel; }, 1400);
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done).catch(fallback);
        } else fallback();

        function fallback() {
          var ta = document.createElement("textarea");
          ta.value = text;
          ta.setAttribute("readonly", "");
          ta.style.position = "fixed";
          ta.style.left = "-9999px";
          document.body.appendChild(ta);
          ta.select();
          try {
            document.execCommand("copy");
            done();
          } catch (err) { /* ignore */ }
          document.body.removeChild(ta);
        }
      });
    });
  }

  /* —— Term tooltips (data-term) —— */
  var glossaryCache = null;
  var tipEl = null;

  function ensureTipEl() {
    if (tipEl) return tipEl;
    tipEl = document.createElement("div");
    tipEl.className = "term-tip";
    tipEl.setAttribute("role", "tooltip");
    tipEl.hidden = true;
    document.body.appendChild(tipEl);
    return tipEl;
  }

  function showTermTip(trigger, text, word) {
    var tip = ensureTipEl();
    tip.innerHTML = "<span class=\"term-tip__word\">" + escapeHtml(word) + "</span>" + escapeHtml(text);
    tip.hidden = false;
    positionTip(trigger, tip);
  }

  function hideTermTip() {
    if (tipEl) tipEl.hidden = true;
  }

  function positionTip(trigger, tip) {
    var rect = trigger.getBoundingClientRect();
    var top = rect.bottom + 8;
    var left = Math.min(rect.left, window.innerWidth - tip.offsetWidth - 12);
    if (top + tip.offsetHeight > window.innerHeight - 8) top = rect.top - tip.offsetHeight - 8;
    tip.style.top = Math.max(8, top) + "px";
    tip.style.left = Math.max(8, left) + "px";
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function loadGlossary(cb) {
    if (glossaryCache) {
      cb(glossaryCache);
      return;
    }
    fetch(assetUrl("glossary.json"))
      .then(function (r) { return r.ok ? r.json() : {}; })
      .catch(function () { return {}; })
      .then(function (data) {
        glossaryCache = data || {};
        cb(glossaryCache);
      });
  }

  function initTermTooltips() {
    loadGlossary(function (glossary) {
      document.querySelectorAll("[data-term]").forEach(function (el) {
        var key = el.getAttribute("data-term");
        var lang = currentLang();
        var entry = glossary[key];
        var def = el.getAttribute("data-term-def") || (entry && (entry[lang] || entry.id || entry.en)) || el.getAttribute("title") || "";
        if (def) el.setAttribute("aria-describedby", "tip-" + key);
        function open() {
          if (!def) return;
          showTermTip(el, def, key);
        }
        el.addEventListener("mouseenter", open);
        el.addEventListener("focus", open);
        el.addEventListener("mouseleave", hideTermTip);
        el.addEventListener("blur", hideTermTip);
      });
    });
  }

  /* —— Wizard —— */
  function initWizard() {
    document.querySelectorAll("[data-wizard]").forEach(function (wizard) {
      var steps = wizard.querySelectorAll("[data-wizard-step]");
      var result = wizard.querySelector("[data-wizard-result]");
      var answers = {};
      var idx = 0;

      function showStep(i) {
        steps.forEach(function (step, si) {
          step.hidden = si !== i;
        });
      }

      showStep(0);

      wizard.querySelectorAll("[data-wizard-answer]").forEach(function (btn) {
        btn.addEventListener("click", function () {
          var step = btn.closest("[data-wizard-step]");
          if (!step) return;
          var q = step.getAttribute("data-wizard-step");
          answers[q] = btn.getAttribute("data-wizard-answer");
          btn.parentElement.querySelectorAll("[data-wizard-answer]").forEach(function (b) {
            b.setAttribute("aria-pressed", b === btn ? "true" : "false");
          });
          idx += 1;
          if (idx < steps.length) {
            showStep(idx);
          } else {
            renderWizardResult(wizard, result, answers);
          }
        });
      });

      var reset = wizard.querySelector("[data-wizard-reset]");
      if (reset) {
        reset.addEventListener("click", function () {
          idx = 0;
          answers = {};
          if (result) result.hidden = true;
          showStep(0);
        });
      }
    });
  }

  function renderWizardResult(wizard, resultEl, answers) {
    if (!resultEl) return;
    var rules = wizard.getAttribute("data-wizard-rules");
    var mode = "both";
    var sign = "hmac";
    if (rules === "builtin") {
      if (answers.secret === "yes") mode = answers.shared === "yes" ? "both" : "aead";
      else mode = "hmac";
      if (answers.nonrep === "yes") sign = "ed25519";
      if (answers.lb === "yes") resultEl.setAttribute("data-needs-replay-store", "true");
    }
    var modeEl = resultEl.querySelector("[data-rec-mode]");
    var signEl = resultEl.querySelector("[data-rec-sign]");
    if (modeEl) modeEl.textContent = mode;
    if (signEl) signEl.textContent = sign;
    resultEl.hidden = false;
    resultEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  /* —— Checklist (localStorage) —— */
  function initChecklist() {
    document.querySelectorAll("[data-checklist]").forEach(function (list) {
      var id = list.getAttribute("data-checklist") || "default";
      var key = STORAGE_CHECKLIST + ":" + id;
      var saved = {};
      if (local) {
        try {
          saved = JSON.parse(local.getItem(key) || "{}");
        } catch (e) {
          saved = {};
        }
      }
      list.querySelectorAll('input[type="checkbox"]').forEach(function (input) {
        var itemKey = input.name || input.id || input.value;
        if (saved[itemKey]) input.checked = true;
        toggleChecklistRow(input);
        input.addEventListener("change", function () {
          saved[itemKey] = input.checked;
          if (local) local.setItem(key, JSON.stringify(saved));
          toggleChecklistRow(input);
        });
      });
      var resetBtn = list.parentElement && list.parentElement.querySelector("[data-checklist-reset]");
      if (resetBtn) {
        resetBtn.addEventListener("click", function () {
          if (local) local.removeItem(key);
          list.querySelectorAll('input[type="checkbox"]').forEach(function (input) {
            input.checked = false;
            toggleChecklistRow(input);
          });
        });
      }
    });
  }

  function toggleChecklistRow(input) {
    var li = input.closest("li");
    if (li) li.classList.toggle("is-checked", input.checked);
  }

  /* —— Search modal —— */
  var searchIndex = null;
  var searchLoadPromise = null;

  function loadSearchIndex() {
    if (searchIndex) return Promise.resolve(searchIndex);
    if (searchLoadPromise) return searchLoadPromise;
    searchLoadPromise = fetch(assetUrl("search-index.json"))
      .then(function (r) {
        if (!r.ok) throw new Error("search-index missing");
        return r.json();
      })
      .then(function (data) {
        searchIndex = Array.isArray(data) ? data : data.items || [];
        return searchIndex;
      })
      .catch(function () {
        searchIndex = [];
        return searchIndex;
      });
    return searchLoadPromise;
  }

  function initSearch() {
    var modal = document.querySelector("[data-search-modal]");
    if (!modal) return;
    var input = modal.querySelector("[data-search-input]");
    var results = modal.querySelector("[data-search-results]");
    var loading = modal.querySelector("[data-search-loading]");
    var empty = modal.querySelector("[data-search-empty]");
    var openers = document.querySelectorAll("[data-search-open]");

    function openModal() {
      modal.hidden = false;
      if (input) {
        input.value = "";
        input.focus();
      }
      if (loading) loading.hidden = false;
      if (empty) empty.hidden = true;
      if (results) results.innerHTML = "";
      loadSearchIndex().then(function () {
        if (loading) loading.hidden = true;
        renderSearch("");
      });
    }

    function closeModal() {
      modal.hidden = true;
    }

    openers.forEach(function (btn) {
      btn.addEventListener("click", function (e) {
        e.preventDefault();
        openModal();
      });
    });

    modal.addEventListener("click", function (e) {
      if (e.target === modal) closeModal();
    });

    document.addEventListener("keydown", function (e) {
      var mod = e.ctrlKey || e.metaKey;
      if (mod && e.key.toLowerCase() === "k") {
        e.preventDefault();
        openModal();
      }
      if (e.key === "/" && !isEditableTarget(e.target)) {
        e.preventDefault();
        openModal();
      }
      if (e.key === "Escape" && !modal.hidden) closeModal();
    });

    if (input) {
      input.addEventListener("input", function () {
        renderSearch(input.value.trim());
      });
    }

    function renderSearch(q) {
      if (!results) return;
      var lang = currentLang();
      loadSearchIndex().then(function (items) {
        var filtered = items.filter(function (item) {
          if (item.lang && item.lang !== lang) return false;
          if (!q) return true;
          var hay = (item.title + " " + (item.snippet || "") + " " + (item.keywords || "")).toLowerCase();
          return hay.indexOf(q.toLowerCase()) !== -1;
        }).slice(0, 12);
        results.innerHTML = "";
        if (!filtered.length) {
          if (empty) empty.hidden = false;
          return;
        }
        if (empty) empty.hidden = true;
        filtered.forEach(function (item, i) {
          var li = document.createElement("li");
          var a = document.createElement("a");
          a.href = guideUrl(item.url || (currentLang() + "/index.html"));
          a.innerHTML =
            "<div class=\"search-hit__title\">" + escapeHtml(item.title || "") + "</div>" +
            "<div class=\"search-hit__meta\">" + escapeHtml(item.category || "") + "</div>" +
            (item.snippet ? "<p class=\"search-hit__snippet\">" + escapeHtml(item.snippet) + "</p>" : "");
          if (i === 0) a.classList.add("is-focused");
          li.appendChild(a);
          results.appendChild(li);
        });
      });
    }
  }

  function isEditableTarget(el) {
    if (!el || !el.tagName) return false;
    var tag = el.tagName.toLowerCase();
    return tag === "input" || tag === "textarea" || tag === "select" || el.isContentEditable;
  }

  /* —— Scrollspy (TOC) —— */
  function initScrollspy() {
    var toc = document.querySelector(".site-toc nav");
    var main = document.querySelector(".site-main, .prose");
    if (!toc || !main) return;
    var links = toc.querySelectorAll('a[href^="#"]');
    if (!links.length) return;
    var headings = [];
    links.forEach(function (link) {
      var id = link.getAttribute("href").slice(1);
      var h = document.getElementById(id);
      if (h) headings.push({ id: id, el: h, link: link });
    });
    if (!headings.length) return;

    function setActive(id) {
      links.forEach(function (a) {
        a.classList.toggle("is-active", a.getAttribute("href") === "#" + id);
      });
    }

    if ("IntersectionObserver" in window) {
      var visible = new Map();
      var observer = new IntersectionObserver(
        function (entries) {
          entries.forEach(function (entry) {
            if (entry.isIntersecting) visible.set(entry.target.id, entry.intersectionRatio);
            else visible.delete(entry.target.id);
          });
          var best = null;
          var bestRatio = 0;
          visible.forEach(function (ratio, hid) {
            if (ratio >= bestRatio) {
              bestRatio = ratio;
              best = hid;
            }
          });
          if (best) setActive(best);
        },
        { rootMargin: "-20% 0px -65% 0px", threshold: [0, 0.1, 0.5, 1] }
      );
      headings.forEach(function (h) { observer.observe(h.el); });
    } else {
      window.addEventListener("scroll", function () {
        var y = window.scrollY + 100;
        var current = headings[0].id;
        headings.forEach(function (h) {
          if (h.el.offsetTop <= y) current = h.id;
        });
        setActive(current);
      });
    }
  }

  function init() {
    if (ensureLangTrailingSlash()) return;
    fixRelativeNavLinks();
    initTheme();
    initLang();
    initSidebar();
    initTabs();
    initCopyCode();
    initTermTooltips();
    initWizard();
    initChecklist();
    initSearch();
    initScrollspy();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
