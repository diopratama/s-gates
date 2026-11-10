import os
import tempfile


_test_data_dir = tempfile.mkdtemp(prefix="sgates_test_suite_")
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(_test_data_dir, 'test_sgates.db')}"
os.environ["EVIDENCE_VAULT_DIR"] = os.path.join(_test_data_dir, "evidence_vault")
os.environ["SEED_DEMO_ASSESSMENTS"] = "true"
os.environ["ENABLE_DEMO_ROLE_SWITCHER"] = "true"
os.environ["APP_ENV"] = "test"
os.environ["ADMIN_EMAIL"] = "test-admin@example.test"
os.environ["ADMIN_PASSWORD"] = "test-admin-password-only-for-tests"
os.environ["SECRET_KEY"] = "test-secret-key-for-isolated-test-suite-only-32-chars"
