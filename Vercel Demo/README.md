# Cadence PII Guard — Vercel sample-only demo

This is a static portfolio demo. It uses two fictional, built-in text examples to demonstrate deterministic PII pattern matching, tagged redaction, source traceability, and a reviewer approval gate.

## Privacy and scope

- There is no file picker, upload endpoint, API, database, analytics, or external model call.
- Detection runs in the visitor's browser on the fixed example text in `index.html`.
- Do not add real resumes, customer records, or other sensitive data to this public demo.
- This version does not extract DOCX/PDF files and does not run OCR. The separate local Python app remains the version for document extraction and scanned PDF OCR.
- The examples demonstrate a limited set of deterministic rules; this is not a universal PII detector or production security service.

## Deploy to Vercel

This folder contains a plain static `index.html`, so it does not need a Python server, build step, or Vercel Function.

1. Install Node.js if it is not already installed, then open PowerShell.
2. Change to this folder, for example:

   ```powershell
   cd "$env:USERPROFILE\.codex\.chatgpt-projects\g-p-6ac33433cdc881918aee28e6bc9fe061\outputs\Cadence_PII_Guard_Vercel_Demo"
   ```

   If your project folder is elsewhere, use that extracted folder path instead.

3. Create a Vercel preview deployment:

   ```powershell
   npx vercel
   ```

4. Follow the prompts to sign in, create a new project, and use the current folder as its root. For a plain static project, leave the build command empty and set the output directory to `.` if prompted.
5. Open the preview URL and try both built-in examples. Check the tagged output, traceability, approval checkbox, and sample download.
6. To publish that reviewed site to the production URL, run:

   ```powershell
   npx vercel --prod
   ```

Vercel's CLI supports preview and production deployments from a local project directory; review the preview URL before publishing production: [Deploying a project from the CLI](https://vercel.com/docs/projects/deploy-from-cli).
