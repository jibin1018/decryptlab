/* DecryptLab — 화면 렌더링과 라우팅
 * 라우트: #/            → 주제 선택(홈)
 *         #/카테고리     → 카테고리의 첫 도구 (준비 중이면 안내 화면)
 *         #/카테고리/도구
 */
(function () {
  'use strict';

  const DL = window.DecryptLab;
  const { CATEGORIES, utf8, utf8Decode, toHex } = DL;
  const app = document.getElementById('app');

  // 도구를 바꿔도 입력은 유지해서, 같은 문자열을 여러 도구에 바로 시험해 볼 수 있게 한다.
  const state = { input: '', file: null, query: '', toolMode: {}, options: {} };
  let runId = 0;
  let debounceTimer;

  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const pad2 = (n) => String(n).padStart(2, '0');
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* 저장 불가 환경 */ } },
  };

  // 새로고침해도 입력·선택한 옵션·모드가 그대로 남도록 로컬에 저장/복원한다.
  // (모두 이 브라우저 안에만 저장되며 외부로 전송되지 않는다. 열어 둔 파일은 저장하지 않는다.)
  const STATE_KEY = 'dl-state';
  (function restoreState() {
    try {
      const saved = JSON.parse(store.get(STATE_KEY) || '{}');
      if (typeof saved.input === 'string') state.input = saved.input;
      if (saved.options && typeof saved.options === 'object') state.options = saved.options;
      if (saved.toolMode && typeof saved.toolMode === 'object') state.toolMode = saved.toolMode;
    } catch { /* 저장된 상태 없음/손상 */ }
  })();
  let persistTimer;
  function persist() {
    clearTimeout(persistTimer);
    persistTimer = setTimeout(() => {
      // 지나치게 큰 입력은 저장하지 않는다 (localStorage 한도 보호).
      const input = state.input.length > 200000 ? '' : state.input;
      store.set(STATE_KEY, JSON.stringify({ input, options: state.options, toolMode: state.toolMode }));
    }, 200);
  }

  /* ---------- 모드·옵션 ---------- */
  const DEFAULT_MODES = [{ id: 'encode', label: '인코딩' }, { id: 'decode', label: '디코딩' }];
  const MODE_TEXT = {
    encode: ['평문', '인코딩 결과', '변환할 텍스트를 입력하세요'],
    decode: ['인코딩된 값', '디코딩 결과', '디코딩할 값을 입력하세요'],
    encrypt: ['평문', '암호문', '암호화할 내용을 입력하세요'],
    decrypt: ['암호문', '평문', '복호화할 암호문을 입력하세요'],
  };
  const modesOf = (tool) => tool.modes || DEFAULT_MODES;
  function currentMode(tool) {
    const modes = modesOf(tool);
    const saved = modes.find((m) => m.id === state.toolMode[tool.id]);
    return saved || modes.find((m) => m.id === 'decode' || m.id === 'decrypt') || modes[0];
  }
  const modeText = (mode) => {
    const [i, o, p] = MODE_TEXT[mode.id] || ['입력', '결과', '여기에 입력하세요'];
    return { inLabel: mode.inLabel || i, outLabel: mode.outLabel || o, placeholder: mode.placeholder || p };
  };
  function optionValues(tool) {
    if (!state.options[tool.id]) state.options[tool.id] = Object.fromEntries((tool.options || []).map((o) => [o.id, o.default]));
    return state.options[tool.id];
  }
  function visibleOptions(tool, mode) {
    const vals = optionValues(tool);
    return (tool.options || []).filter((o) => {
      if (o.mode && ![].concat(o.mode).includes(mode.id)) return false;
      return !o.when || o.when(vals);
    });
  }

  /* ---------- 라우팅 ---------- */
  function parseRoute() {
    const [catId, toolId] = location.hash.replace(/^#\/?/, '').split('/');
    const cat = CATEGORIES.find((c) => c.id === catId);
    if (!cat) return { view: 'home' };
    if (!cat.tools.length) return { view: 'soon', cat };
    return { view: 'tool', cat, tool: cat.tools.find((t) => t.id === toolId) || cat.tools[0] };
  }
  function render() {
    const route = parseRoute();
    if (route.view === 'home') renderHome();
    else renderWorkspace(route.cat, route.tool || null);
    window.scrollTo(0, 0);
  }

  /* ---------- 홈 ---------- */
  function cardHTML(c) {
    const soon = !c.tools.length;
    const plannedCount = (c.planned || []).length;
    const meta = soon
      ? `준비 중 · 도구 ${plannedCount}개 예정`
      : `${c.tools.length}개 도구${plannedCount ? ` · ${plannedCount}개 준비 중` : ''}`;
    return `
      <a class="topic-card accent-${c.color}${soon ? ' soon' : ''}" href="#/${c.id}">
        ${soon ? '<span class="badge">준비 중</span>' : ''}
        <h2>${esc(c.name)}</h2>
        <p>${esc(c.desc)}</p>
        <div class="meta">${meta}</div>
      </a>`;
  }
  function searchResults(q) {
    const needle = q.trim().toLowerCase();
    const hits = [];
    for (const c of CATEGORIES) {
      for (const t of c.tools) {
        if (`${t.name} ${t.short} ${t.desc}`.toLowerCase().includes(needle)) hits.push({ c, t });
      }
      for (const [name, short] of c.planned || []) {
        if (`${name} ${short}`.toLowerCase().includes(needle)) hits.push({ c, planned: { name, short } });
      }
    }
    if (!hits.length) return '<p class="empty">일치하는 도구가 없습니다.</p>';
    return `<div class="results">${hits.map(({ c, t, planned }) => (t
      ? `<a class="result accent-${c.color}" href="#/${c.id}/${t.id}"><span class="dot"></span><span><b>${esc(t.name)}</b><small>${esc(c.name)} · ${esc(t.short)}</small></span></a>`
      : `<div class="result disabled accent-${c.color}"><span class="dot"></span><span><b>${esc(planned.name)} <em>준비 중</em></b><small>${esc(c.name)} · ${esc(planned.short)}</small></span></div>`)).join('')}</div>`;
  }
  function renderHome() {
    document.title = 'DecryptLab';
    const total = CATEGORIES.reduce((n, c) => n + c.tools.length, 0);
    app.innerHTML = `
      <main class="home">
        <h1>무엇을 풀어볼까요?</h1>
        <p class="lead">인코딩·고전 암호·대칭/공개키·해시·압축·토큰 — 모두 브라우저 안에서 처리됩니다.</p>
        <div class="search">
          <input id="search" type="search" placeholder="도구 검색 — 예: base64, aes, 비즈네르, jwt" value="${esc(state.query)}" autocomplete="off" aria-label="도구 검색">
          <span class="total">${total}개 도구</span>
        </div>
        <div id="home-body">${state.query.trim() ? searchResults(state.query) : `<div class="card-grid">${CATEGORIES.map(cardHTML).join('')}</div>`}</div>
      </main>`;
    const input = app.querySelector('#search');
    input.addEventListener('input', () => {
      state.query = input.value;
      app.querySelector('#home-body').innerHTML = state.query.trim() ? searchResults(state.query) : `<div class="card-grid">${CATEGORIES.map(cardHTML).join('')}</div>`;
    });
  }

  /* ---------- 작업 공간 ---------- */
  function sidebarHTML(cat, tool) {
    const planned = cat.planned || [];
    return `
      <aside class="sidebar" aria-label="${esc(cat.name)} 목차">
        <a class="back" href="#/">← 전체 주제</a>
        <div class="side-head"><h2>${esc(cat.name)}</h2></div>
        <nav class="toc">
          ${cat.tools.map((t, i) => `
            <a class="toc-item" href="#/${cat.id}/${t.id}" ${t === tool ? 'aria-current="page"' : ''}>
              <span class="num">${pad2(i + 1)}</span>
              <span><b>${esc(t.name)}</b><small>${esc(t.short)}</small></span>
            </a>`).join('')}
          ${planned.map(([name, short], i) => `
            <div class="toc-item disabled" aria-disabled="true">
              <span class="num">${pad2(cat.tools.length + i + 1)}</span>
              <span><b>${esc(name)} <em>준비 중</em></b><small>${esc(short)}</small></span>
            </div>`).join('')}
        </nav>
        <div class="side-other">
          <h3>다른 주제</h3>
          ${CATEGORIES.filter((c) => c !== cat).map((c) => `
            <a class="accent-${c.color}" href="#/${c.id}"><span class="dot"></span>${esc(c.name)}${c.tools.length ? '' : ' <em>준비 중</em>'}</a>`).join('')}
        </div>
      </aside>`;
  }

  function optionHTML(o, value) {
    const id = `opt-${o.id}`;
    const wide = o.wide || o.type === 'textarea' ? ' wide' : '';
    if (o.type === 'checkbox') {
      return `<label class="opt"><input type="checkbox" id="${id}" data-opt="${o.id}" ${value ? 'checked' : ''}>${esc(o.label)}</label>`;
    }
    if (o.type === 'select') {
      return `<label class="opt${wide}" for="${id}">${esc(o.label)}
        <select id="${id}" data-opt="${o.id}">
          ${o.choices.map(([v, l]) => `<option value="${esc(v)}" ${String(value) === v ? 'selected' : ''}>${esc(l)}</option>`).join('')}
        </select></label>`;
    }
    if (o.type === 'textarea') {
      return `<label class="opt wide stacked" for="${id}">${esc(o.label)}
        <textarea id="${id}" data-opt="${o.id}" rows="4" spellcheck="false" placeholder="${esc(o.placeholder || '')}">${esc(value)}</textarea></label>`;
    }
    const extra = o.type === 'number' ? `min="${o.min ?? ''}" max="${o.max ?? ''}"` : `placeholder="${esc(o.placeholder || '')}" spellcheck="false" autocomplete="off"`;
    return `<label class="opt${wide}" for="${id}">${esc(o.label)}
      <input type="${o.type}" id="${id}" data-opt="${o.id}" value="${esc(value)}" ${extra}></label>`;
  }

  function renderSoon(cat) {
    return `
      <main class="panel">
        <div class="crumb">${esc(cat.name)}</div>
        <h1>준비 중입니다</h1>
        <div class="soon-box">
          <h3>추가될 도구</h3>
          <ul>${(cat.planned || []).map(([n, s]) => `<li><b>${esc(n)}</b><span>${esc(s)}</span></li>`).join('')}</ul>
        </div>
      </main>`;
  }

  function renderWorkspace(cat, tool) {
    if (!tool) {
      document.title = `${cat.name} · DecryptLab`;
      app.innerHTML = `<div class="workspace accent-${cat.color}">${sidebarHTML(cat, null)}${renderSoon(cat)}</div>`;
      return;
    }
    document.title = `${tool.name} · DecryptLab`;
    const modes = modesOf(tool);
    const mode = currentMode(tool);
    const { inLabel, outLabel, placeholder } = modeText(mode);
    const opts = optionValues(tool);
    const useFile = tool.fileInput && state.file;
    const swappable = modes.length === 2 && !modes.some((m) => m.noInput);
    // 가역 2모드 도구는 양쪽을 모두 편집할 수 있게 하고, 한쪽을 고치면 반대 모드로 변환한다.
    const twoWay = swappable && !useFile;
    const oppMode = twoWay ? modes.find((m) => m !== mode) : null;

    app.innerHTML = `
      <div class="workspace accent-${cat.color}">
        ${sidebarHTML(cat, tool)}
        <main class="panel">
          <div class="crumb">${esc(cat.name)}</div>
          <h1>${esc(tool.name)}</h1>

          <div class="controls">
            ${modes.length > 1 ? `
              <div class="segmented" role="group" aria-label="동작">
                ${modes.map((m) => `<button type="button" data-mode="${m.id}" aria-pressed="${m === mode}">${esc(m.label)}</button>`).join('')}
              </div>` : ''}
            ${visibleOptions(tool, mode).map((o) => optionHTML(o, opts[o.id])).join('')}
          </div>

          <div class="io">
            <section class="pane">
              <div class="pane-head">
                <span class="pane-title">${esc(mode.noInput ? '실행' : inLabel)}<span class="count" id="in-count"></span></span>
                ${mode.noInput ? '' : `
                <div class="pane-actions">
                  ${tool.fileInput ? '<button class="btn" type="button" id="file-btn">파일 열기</button><input type="file" id="file-input" hidden>' : ''}
                  <button class="btn" type="button" id="paste-btn">붙여넣기</button>
                  <button class="btn" type="button" id="clear-btn">지우기</button>
                </div>`}
              </div>
              ${mode.noInput
                ? `<div class="run-box"><p>옵션을 고른 뒤 버튼을 누르세요. 생성된 키는 이 브라우저 안에만 존재합니다.</p><button class="btn primary" type="button" id="run-btn">${esc(mode.label)}</button></div>`
                : `<textarea id="input" spellcheck="false" autocomplete="off" aria-label="${esc(inLabel)}" placeholder="${esc(placeholder)}" ${useFile ? 'readonly' : ''}></textarea>`}
            </section>
            <section class="pane">
              <div class="pane-head">
                <span class="pane-title">${esc(outLabel)}<span class="count" id="out-count"></span></span>
                <div class="pane-actions">
                  ${swappable && !twoWay ? '<button class="btn" type="button" id="swap-btn" title="결과를 입력으로 옮기고 동작을 바꿉니다">⇄ 입력으로</button>' : ''}
                  <button class="btn" type="button" id="copy-btn">복사</button>
                </div>
              </div>
              <textarea id="output" spellcheck="false" autocomplete="off" aria-label="${esc(outLabel)}" ${twoWay ? `placeholder="여기에 ${esc(outLabel)}을 입력하면 반대로 변환됩니다"` : 'readonly aria-live="polite"'}></textarea>
              <div class="status" id="status" role="status"></div>
            </section>
          </div>
        </main>
      </div>`;

    const $in = app.querySelector('#input');
    const run = (immediate) => schedule(tool, mode, immediate);

    if ($in) {
      $in.value = useFile ? `[파일] ${state.file.name} (${state.file.bytes.length.toLocaleString()} B)\n\n지우기를 누르면 텍스트 입력으로 돌아갑니다.` : state.input;
      $in.addEventListener('input', () => { state.input = $in.value; persist(); run(); });
    }

    // 양방향: 출력칸을 직접 고치면 반대 모드로 변환해 입력칸을 채운다.
    if (twoWay && oppMode) {
      const $out = app.querySelector('#output');
      $out.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        if (!tool.slow) convertReverse(tool, oppMode);
        else { runId++; setStatus('계산 중…'); debounceTimer = setTimeout(() => convertReverse(tool, oppMode), 350); }
      });
    }

    app.querySelectorAll('[data-mode]').forEach((b) => b.addEventListener('click', () => {
      if (b.dataset.mode === mode.id) return;
      state.toolMode[tool.id] = b.dataset.mode;
      persist();
      renderWorkspace(cat, tool);
      const i = app.querySelector('#input'); if (i) i.focus();
    }));

    const hasConditional = (tool.options || []).some((o) => o.when);
    app.querySelectorAll('[data-opt]').forEach((el) => {
      const discrete = el.type === 'checkbox' || el.tagName === 'SELECT';
      el.addEventListener(discrete ? 'change' : 'input', () => {
        opts[el.dataset.opt] = el.type === 'checkbox' ? el.checked : el.value;
        persist();
        // 다른 옵션의 표시 여부가 바뀔 수 있으면 다시 그린다 (텍스트 입력은 포커스 유지를 위해 제외)
        if (discrete && hasConditional) { renderWorkspace(cat, tool); return; }
        if (!mode.noInput) run();
      });
    });

    const clear = app.querySelector('#clear-btn');
    if (clear) clear.addEventListener('click', () => {
      if (state.file && tool.fileInput) { state.file = null; renderWorkspace(cat, tool); return; }
      state.input = ''; persist(); $in.value = ''; $in.focus(); run(true);
    });
    const paste = app.querySelector('#paste-btn');
    if (paste) paste.addEventListener('click', async () => {
      try {
        state.input = await navigator.clipboard.readText();
        persist();
        if (state.file && tool.fileInput) { state.file = null; renderWorkspace(cat, tool); return; }
        $in.value = state.input; run(true);
      } catch { toast('클립보드를 읽을 수 없습니다. 직접 붙여넣어 주세요.'); $in.focus(); }
    });
    const fileBtn = app.querySelector('#file-btn');
    if (fileBtn) {
      const fileInput = app.querySelector('#file-input');
      fileBtn.addEventListener('click', () => fileInput.click());
      fileInput.addEventListener('change', async () => {
        const f = fileInput.files[0];
        if (!f) return;
        if (f.size > 50 * 1024 * 1024) { toast('50 MB보다 큰 파일은 열 수 없습니다.'); return; }
        state.file = { name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) };
        renderWorkspace(cat, tool);
      });
    }
    const runBtn = app.querySelector('#run-btn');
    if (runBtn) runBtn.addEventListener('click', () => run(true));

    app.querySelector('#copy-btn').addEventListener('click', () => copy(app.querySelector('#output').value));
    const swap = app.querySelector('#swap-btn');
    if (swap) swap.addEventListener('click', () => {
      const out = app.querySelector('#output').value;
      if (!out || app.querySelector('#status').classList.contains('error')) return;
      state.input = out;
      state.file = null;
      state.toolMode[tool.id] = modes.find((m) => m !== mode).id;
      renderWorkspace(cat, tool);
    });

    if (mode.noInput) showResult('', `"${mode.label}" 버튼을 누르면 결과가 나타납니다.`);
    else run(true);
  }

  /* ---------- 변환 실행 ---------- */
  function schedule(tool, mode, immediate) {
    clearTimeout(debounceTimer);
    if (immediate || !tool.slow) convert(tool, mode);
    else {
      runId++; // 진행 중이던 이전 결과는 버린다
      setStatus('계산 중…');
      debounceTimer = setTimeout(() => convert(tool, mode), 350);
    }
  }
  function setStatus(msg, cls = '') {
    const $status = app.querySelector('#status');
    if (!$status) return;
    $status.className = `status ${cls}`;
    $status.textContent = msg;
  }
  function showResult(text, msg = '', cls = '') {
    const $out = app.querySelector('#output');
    if (!$out) return;
    $out.value = text;
    app.querySelector('#out-count').textContent = text ? `${Array.from(text).length.toLocaleString()}자` : '';
    setStatus(msg, cls);
  }

  function convert(tool, mode) {
    const id = ++runId;
    const useFile = tool.fileInput && state.file;
    const input = mode.noInput ? '' : useFile ? state.file.bytes : state.input;
    const $inCount = app.querySelector('#in-count');
    if ($inCount) {
      $inCount.textContent = useFile ? `${input.length.toLocaleString()} B`
        : input ? `${Array.from(input).length.toLocaleString()}자 · ${utf8(input).length.toLocaleString()} B` : '';
    }
    const show = (...a) => { if (id === runId) showResult(...a); };

    if (!mode.noInput && !useFile && !input) { show('', '입력하면 바로 결과가 나타납니다.'); return; }
    if (mode.noInput) show('', '생성 중…');

    const fn = tool[mode.id];
    Promise.resolve()
      .then(() => fn(input, optionValues(tool)))
      .then((res) => {
        if (res instanceof Uint8Array) {
          // 바이트 결과는 UTF-8로 해석하고, 실패하면 16진수로 보여준다.
          try { show(utf8Decode(res, true), `${res.length.toLocaleString()} B 처리 완료`, 'ok'); }
          catch { show(toHex(res, false, ' '), `유효한 UTF-8 텍스트가 아니어서 ${res.length.toLocaleString()} B를 16진수로 표시합니다.`, 'warn'); }
        } else if (res && typeof res === 'object' && 'text' in res) show(String(res.text ?? ''), res.note || '', res.cls || '');
        else show(String(res ?? ''), '');
      })
      .catch((err) => show('', `⚠ ${err && err.message ? err.message : '처리할 수 없는 입력입니다.'}`, 'error'));
  }

  // 출력칸 → 입력칸 역방향 변환 (양방향 도구 전용)
  function convertReverse(tool, oppMode) {
    const id = ++runId;
    const $out = app.querySelector('#output');
    const $in = app.querySelector('#input');
    if (!$out || !$in) return;
    const src = $out.value;
    const $outCount = app.querySelector('#out-count');
    if ($outCount) $outCount.textContent = src ? `${Array.from(src).length.toLocaleString()}자` : '';
    const show = (text, msg = '', cls = '') => {
      if (id !== runId) return;
      $in.value = text;
      state.input = text;
      persist();
      const $inCount = app.querySelector('#in-count');
      if ($inCount) $inCount.textContent = text ? `${Array.from(text).length.toLocaleString()}자 · ${utf8(text).length.toLocaleString()} B` : '';
      setStatus(msg, cls);
    };
    if (!src) { show('', '반대쪽에 입력하면 변환됩니다.'); return; }
    Promise.resolve()
      .then(() => tool[oppMode.id](src, optionValues(tool)))
      .then((res) => {
        if (res instanceof Uint8Array) {
          try { show(utf8Decode(res, true), '', 'ok'); }
          catch { show(toHex(res, false, ' '), '유효한 UTF-8 텍스트가 아니어서 16진수로 표시합니다.', 'warn'); }
        } else if (res && typeof res === 'object' && 'text' in res) show(String(res.text ?? ''), res.note || '', res.cls || '');
        else show(String(res ?? ''), '');
      })
      .catch((err) => show('', `⚠ ${err && err.message ? err.message : '처리할 수 없는 입력입니다.'}`, 'error'));
  }

  /* ---------- 유틸 ---------- */
  let toastTimer;
  function toast(msg) {
    let el = document.querySelector('.toast');
    if (!el) { el = document.createElement('div'); el.className = 'toast'; document.body.appendChild(el); }
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 1600);
  }
  async function copy(text) {
    if (!text) return;
    try { await navigator.clipboard.writeText(text); }
    catch {
      const t = document.createElement('textarea');
      t.value = text; document.body.appendChild(t); t.select();
      document.execCommand('copy'); t.remove();
    }
    toast('복사했습니다');
  }

  /* ---------- 테마 ---------- */
  document.getElementById('theme-toggle').addEventListener('click', () => {
    const root = document.documentElement;
    const current = root.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = current === 'dark' ? 'light' : 'dark';
    root.dataset.theme = next;
    store.set('dl-theme', next);
  });

  /* ---------- 맨 위로 스크롤 버튼 ---------- */
  (function scrollTopButton() {
    const btn = document.createElement('button');
    btn.className = 'scroll-top';
    btn.type = 'button';
    btn.setAttribute('aria-label', '맨 위로');
    btn.title = '맨 위로';
    btn.innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><path fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" d="M6 14l6-6 6 6"/></svg>';
    // 일부 환경에서 window의 behavior:'smooth'가 동작하지 않아 직접 애니메이션으로 올린다.
    btn.addEventListener('click', () => {
      const start = window.scrollY || document.documentElement.scrollTop || 0;
      if (start <= 0) return;
      const t0 = performance.now(), dur = 320;
      const step = (now) => {
        const p = Math.min(1, (now - t0) / dur);
        const ease = 1 - Math.pow(1 - p, 3);
        window.scrollTo(0, Math.round(start * (1 - ease)));
        if (p < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    });
    document.body.appendChild(btn);
    const toggle = () => btn.classList.toggle('show', window.scrollY > 300);
    window.addEventListener('scroll', toggle, { passive: true });
    toggle();
  })();

  window.addEventListener('hashchange', render);
  render();
})();
