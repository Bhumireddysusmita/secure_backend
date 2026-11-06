-- Creates the application role and the app + test databases on a local PostgreSQL.
-- Run as a superuser, passing the password as a psql variable (nothing secret is stored here):
--
--   psql -U postgres -h localhost -v app_password='<choose-a-password>' -f backend/scripts/init_db.sql
--
-- Then put the same password in backend/.env (DATABASE_URL / TEST_DATABASE_URL)
-- and run the migrations:  cd backend && alembic upgrade head

SELECT format('CREATE ROLE secure_auth LOGIN PASSWORD %L', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'secure_auth')
\gexec

SELECT 'CREATE DATABASE secure_auth OWNER secure_auth'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'secure_auth')
\gexec

SELECT 'CREATE DATABASE secure_auth_test OWNER secure_auth'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'secure_auth_test')
\gexec
