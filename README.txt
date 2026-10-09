NATIONAL TRADE — RESPONSIVE + NOTIFICATIONS
==========================================

FILES TO REPLACE (BACK UP YOUR CURRENT FILES FIRST):

1) nt_index_mobile.html  -->  C:\Users\Xiao ge\national-trade-backend\public\index.html
2) nt_admin_mobile.html  -->  C:\Users\Xiao ge\national-trade-backend\private\admin.html
3) nt-notify.js         -->  C:\Users\Xiao ge\national-trade-backend\public\nt-notify.js

The ZIP archive already contains those files with the correct filenames and folders:
  public/index.html
  public/nt-notify.js
  private/admin.html

HOW TO USE
- Back up existing public/index.html, private/admin.html and public/nt-notify.js first.
- Extract the ZIP into the national-trade-backend project root, preserving folder names.
- Do not replace server.js, database.js, .env or nationaltrade.db.
- Keep your Node server running: node server.js
- Refresh Chrome with Ctrl+Shift+R.
- Test index and admin on a real phone or Chrome mobile emulation.

CHANGES
- Preserves user and admin interface elements, database calls and existing buttons.
- Native alert() now presents a small top-center toast for user and admin HTML.
- Native confirm() and prompt() calls inside the uploaded HTML are rewritten to await branded dialogs.
- User navigation scrolls horizontally on narrow phone screens without changing tab logic.
- Admin dashboard has a mobile Menu toggle; its tables scroll inside their own containers.
- Main forms, modal dialogs, trading frame and chat sections have mobile sizing improvements.
- Desktop layout largely retains the original styling.

NOT INCLUDED / LIMITATIONS
- admin-login.html is a separate file and was not uploaded, so its original alerts are not changed.
- This is a front-end UI update only; no live payment settlement, real identity verification,
  trading fairness, production security or compliance checks were implemented.
- Original risk/trading controls and browser-storage-dependent features are unchanged.
- Real-device checks (iPhone, Android) and full deployed server integration still need testing.
