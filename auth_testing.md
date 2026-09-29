# CaseVault Authentication Testing

Use the two demo accounts in `/app/memory/test_credentials.md`.

1. POST `/api/auth/login` with `officer_id` and `password`; verify a session cookie and officer profile.
2. GET `/api/auth/me` with the session cookie; verify the same officer.
3. POST `/api/auth/logout`; verify subsequent protected requests return 401.
4. Login as Rahul Sharma and verify upload/edit actions are available.
5. Login as Priya Menon and verify view/download are available while edit/upload return 403.