"""Entry point so ``python -m remora.codegen`` runs the drift check warning-free."""

from remora.codegen.fingerprint import main

raise SystemExit(main())
