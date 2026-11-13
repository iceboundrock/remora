# Issue tracker: GitHub

Issues and PRDs for this repo live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

- Create an issue with `gh issue create --title "..." --body "..."`.
- Read an issue with `gh issue view <number> --comments`.
- List issues with `gh issue list` and filter using the JSON fields when needed.
- Comment on an issue with `gh issue comment <number> --body "..."`.
- Apply or remove labels with `gh issue edit <number> --add-label "..."` or `--remove-label "..."`.
- Close an issue with `gh issue close <number> --comment "..."`.

Infer the repository from `git remote -v`; `gh` does this automatically inside the clone.
