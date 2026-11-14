# MadHacks 2026

Shared repository for our hackathon team. Project idea and tech stack will be decided together.

## Get started

Accept your GitHub collaborator invitation, then clone the repository:

```bash
git clone https://github.com/BlackMaksim/madhacks-2026.git
cd madhacks-2026
```

Setup and run instructions will be added after we choose the tech stack.

## Team workflow

1. Agree on a small task and who owns it. Use GitHub Issues to track tasks.
2. Start from the latest main and create your own branch:

```bash
git switch main
git pull --ff-only origin main
git switch -c feature/your-task
```

3. Make changes, check them locally, and commit only the files you intend to share:

```bash
git add path/to/file
git commit -m "Describe your change"
git push -u origin feature/your-task
```

4. Open a pull request from your branch into main. Explain what changed and how to test it.
5. Ask a teammate to review, then merge when ready. Keep main working for the demo.
6. Before starting the next task, switch to main and pull again.

Use a different branch name for each task. Coordinate before editing the same files. If Git reports a conflict, resolve it together; do not force-push main.

## First team meeting

- Choose the problem, target user, and smallest useful demo.
- Pick the tech stack and agree on how to run it locally.
- Split the first tasks and decide which files each person owns.
- Record the demo flow and submission requirements.
