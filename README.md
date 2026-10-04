# termpaper

> A command-line checker for SPF, DKIM, and DMARC alignment in an email message.

## Overview

The Python script reads a raw `.eml` file and evaluates sender-domain authentication using the supplied sending IP, envelope sender, and HELO domain. Despite the repository name, the current code is an email-authentication experiment.

## What’s in this repo

- Parsing a saved email message
- SPF lookup and DKIM verification
- DMARC alignment evaluation and a printed result summary

## Stack

Python, DNS lookups, `dnspython`, `pyspf`, and `dkimpy`.

## Getting started

1. Install the Python packages required by `app.py` in a virtual environment.
2. Run `python app.py <email_file> <client_ip> <smtp_mail_from> <helo_domain>`; use `-` for an unavailable sender or HELO value.
3. A sample message file, `email.eml`, is included; supply the sending details relevant to the message you are testing.

## Notes

The output is diagnostic and depends on correct sender and DNS information. Do not treat a single result as proof that an email is safe or authentic.
