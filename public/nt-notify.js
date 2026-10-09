/* National Trade: accessible centered notifications and non-blocking dialogs.
 * This file replaces visual feedback only. No backend, balances, or business rules are changed.
 */
(function () {
    'use strict';

    const css = `
#nt-toast-root{position:fixed;top:max(14px,env(safe-area-inset-top));left:50%;transform:translateX(-50%);width:min(410px,calc(100vw - 28px));z-index:2147483000;display:flex;flex-direction:column;gap:10px;pointer-events:none;box-sizing:border-box}
.nt-toast{display:flex;align-items:flex-start;gap:12px;padding:15px 16px;background:#17202f;border:1px solid #344156;border-top:3px solid var(--nt-color,#3b82f6);border-radius:14px;box-shadow:0 16px 48px #0009;color:#f8fafc;pointer-events:auto;animation:ntToastIn .24s ease-out;font:inherit;max-width:100%;box-sizing:border-box}
.nt-toast-icon{font-size:18px;color:var(--nt-color,#3b82f6);font-weight:800;min-width:20px;text-align:center;line-height:1.35}
.nt-toast-body{flex:1;min-width:0}.nt-toast-title{font-size:13px;font-weight:800;margin-bottom:3px}.nt-toast-message{font-size:12px;line-height:1.6;color:#c6ceda;overflow-wrap:anywhere}
.nt-toast-close{border:0;background:transparent;color:#94a3b8;cursor:pointer;font-size:21px;line-height:1;padding:0 0 4px 5px;min-height:25px;min-width:24px}
@keyframes ntToastIn{from{opacity:0;transform:translateY(-16px)}to{opacity:1;transform:translateY(0)}}
#nt-dialog-overlay{position:fixed;inset:0;background:#020617c9;backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px);z-index:2147483001;display:flex;align-items:center;justify-content:center;padding:16px;box-sizing:border-box}
#nt-dialog-overlay *{box-sizing:border-box}
.nt-dialog{background:#151c29;border:1px solid #354154;border-radius:18px;box-shadow:0 20px 70px #000c;color:#fff;width:min(430px,100%);padding:22px 22px 18px;max-height:min(85dvh,700px);overflow:auto;font-family:inherit}
.nt-dialog-title{display:flex;align-items:center;gap:10px;font-size:16px;font-weight:800;line-height:1.4}
.nt-dialog-glyph{border-radius:10px;background:#2563eb1f;color:#60a5fa;padding:6px 10px}
.nt-dialog-text{margin:15px 0 16px;color:#cad3e2;font-size:13px;line-height:1.65;white-space:pre-wrap;overflow-wrap:anywhere}
.nt-dialog-input{width:100%;min-height:44px;background:#0b1220;color:#fff;border:1px solid #45516a;padding:11px 12px;font-size:16px;border-radius:10px;outline:none;margin:0 0 16px}
.nt-dialog-input:focus{border-color:#60a5fa;box-shadow:0 0 0 2px #3b82f63b}
.nt-dialog-actions{display:flex;justify-content:flex-end;gap:10px;flex-wrap:wrap}
.nt-dialog-btn{border:1px solid #374151;padding:11px 18px;border-radius:10px;min-height:44px;font-size:13px;font-weight:700;cursor:pointer;color:#fff;background:#374151}
.nt-dialog-btn-primary{background:#2563eb;border-color:#2563eb}.nt-dialog-btn-danger{background:#dc2626;border-color:#dc2626}
.nt-dialog-btn:focus-visible,.nt-toast-close:focus-visible{outline:2px solid #60a5fa;outline-offset:2px}
@media(max-width:480px){#nt-toast-root{top:max(12px,env(safe-area-inset-top));width:calc(100vw - 24px)}.nt-toast{padding:12px}.nt-dialog{padding:18px}.nt-dialog-actions{display:grid;grid-template-columns:1fr 1fr}.nt-dialog-btn{padding:11px 6px}}
@media(prefers-reduced-motion:reduce){.nt-toast{animation:none}}
`;
    const style = document.createElement('style');
    style.id = 'nt-ui-styles';
    style.textContent = css;
    document.head.appendChild(style);

    function getRoot() {
        let root = document.getElementById('nt-toast-root');
        if (!root) {
            root = document.createElement('div');
            root.id = 'nt-toast-root';
            document.body.appendChild(root);
        }
        return root;
    }

    const variants = {
        success: {title: 'Success', color: '#22c55e', icon: '✓'},
        error:   {title: 'Error', color: '#ef4444', icon: '×'},
        warning: {title: 'Warning', color: '#f59e0b', icon: '!'},
        info:    {title: 'Notification', color: '#60a5fa', icon: 'i'}
    };
    window.ntNotify = function ntNotify(message, type = 'info') {
        const cfg = variants[type] || variants.info;
        const root = getRoot();
        const toast = document.createElement('div');
        toast.className = 'nt-toast';
        toast.style.setProperty('--nt-color', cfg.color);
        toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
        const glyph = document.createElement('span');
        glyph.className = 'nt-toast-icon';
        glyph.textContent = cfg.icon;
        const body = document.createElement('div');
        body.className = 'nt-toast-body';
        const title = document.createElement('div');
        title.className = 'nt-toast-title';
        title.textContent = cfg.title;
        const detail = document.createElement('div');
        detail.className = 'nt-toast-message';
        detail.textContent = String(message ?? '');
        body.append(title, detail);
        const close = document.createElement('button');
        close.className = 'nt-toast-close';
        close.type = 'button';
        close.setAttribute('aria-label','Close notification');
        close.textContent = '×';
        toast.append(glyph,body,close);
        root.appendChild(toast);
        // Limit stack height on mobile; remove oldest toast first.
        while (root.children.length > 3) root.firstElementChild.remove();
        const timeout = window.setTimeout(() => toast.remove(), 4500);
        close.addEventListener('click', () => {window.clearTimeout(timeout); toast.remove();});
        return toast;
    };

    // A single dialog queue prevents confirmation boxes from overlapping.
    let dialogQueue = Promise.resolve();
    function dialog(kind, message, defaultValue = '') {
        const run = () => new Promise((resolve) => {
            const overlay = document.createElement('div');
            overlay.id = 'nt-dialog-overlay';
            const card = document.createElement('div');
            card.className = 'nt-dialog';
            card.setAttribute('role', 'dialog');
            card.setAttribute('aria-modal', 'true');
            const title = document.createElement('div');
            title.className = 'nt-dialog-title';
            const glyph = document.createElement('span');
            glyph.className = 'nt-dialog-glyph';
            glyph.textContent = kind === 'prompt' ? '✎' : '?';
            const titleText = document.createElement('span');
            titleText.textContent = kind === 'prompt' ? 'Enter Details' : 'Please Confirm';
            title.append(glyph,titleText);
            const description = document.createElement('div');
            description.className = 'nt-dialog-text';
            description.id = 'nt-dialog-description';
            description.textContent = String(message ?? '');
            card.setAttribute('aria-describedby','nt-dialog-description');
            card.append(title,description);
            let input = null;
            if (kind === 'prompt') {
                input = document.createElement('input');
                input.className = 'nt-dialog-input';
                input.type = /password/i.test(String(message)) ? 'password' : 'text';
                input.autocomplete = 'off';
                // Do not prefill password inputs with an existing password.
                input.value = input.type === 'password' ? '' : String(defaultValue ?? '');
                card.appendChild(input);
            }
            const actions = document.createElement('div');
            actions.className = 'nt-dialog-actions';
            const cancel = document.createElement('button');
            cancel.type = 'button';
            cancel.className = 'nt-dialog-btn';
            cancel.textContent = 'Cancel';
            const approve = document.createElement('button');
            approve.type = 'button';
            approve.className = 'nt-dialog-btn nt-dialog-btn-primary';
            const destructive = /\b(reject|delete|remove|block|deduct|force release|reset password)\b/i.test(String(message));
            if (destructive) approve.classList.add('nt-dialog-btn-danger');
            approve.textContent = kind === 'prompt' ? 'Continue' : 'Confirm';
            actions.append(cancel,approve);
            card.appendChild(actions);
            overlay.appendChild(card);
            document.body.appendChild(overlay);
            const previousFocus = document.activeElement;
            const oldOverflow = document.body.style.overflow;
            document.body.style.overflow = 'hidden';
            let settled = false;
            const finish = (value) => {
                if (settled) return;
                settled = true;
                document.removeEventListener('keydown', handleKeys, true);
                overlay.remove();
                document.body.style.overflow = oldOverflow;
                if (previousFocus && previousFocus.isConnected && typeof previousFocus.focus === 'function') previousFocus.focus();
                resolve(value);
            };
            function handleKeys(e) {
                if (e.key === 'Escape') {e.preventDefault(); finish(kind === 'prompt' ? null : false);}
                else if (e.key === 'Enter' && (kind === 'prompt' || document.activeElement === approve)) {
                    e.preventDefault(); finish(kind === 'prompt' ? input.value : true);
                } else if (e.key === 'Tab') {
                    const list = kind === 'prompt' ? [input,cancel,approve] : [cancel,approve];
                    const first = list[0], last = list[list.length-1];
                    if (e.shiftKey && document.activeElement === first) {e.preventDefault();last.focus();}
                    else if (!e.shiftKey && document.activeElement === last) {e.preventDefault();first.focus();}
                }
            }
            document.addEventListener('keydown', handleKeys, true);
            cancel.addEventListener('click', () => finish(kind === 'prompt' ? null : false));
            approve.addEventListener('click', () => finish(kind === 'prompt' ? input.value : true));
            overlay.addEventListener('click', (e) => {if (e.target === overlay) finish(kind === 'prompt' ? null : false);});
            (input || cancel).focus();
        });
        const next = dialogQueue.then(run,run);
        dialogQueue = next.then(()=>undefined,()=>undefined);
        return next;
    }
    window.ntConfirm = (message) => dialog('confirm',message);
    window.ntPrompt = (message,defaultValue = '') => dialog('prompt',message,defaultValue);

    // Covers legacy alert() calls and inline onclick alerts without touching business logic.
    window.alert = function (message) {
        const content = String(message ?? '');
        let type = 'info';
        if (/\b(error|failed|invalid|denied|mismatch|wrong|cannot|can't|not found|blocked|quota|insufficient|expired)\b/i.test(content)) type = 'error';
        else if (/\b(warn|please|must|require|select|enter|not connected|test mode|pending)\b/i.test(content)) type = 'warning';
        else if (/\b(success|approved|submitted|saved|sent|updated|completed|released|welcome|claimed)\b/i.test(content)) type = 'success';
        window.ntNotify(content,type);
    };
})();
