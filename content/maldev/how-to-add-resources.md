---
title: "How to Add Resources to Your Hugo Site"
date: 2025-10-27
tags: ["hugo", "tutorial", "guide"]
---

# How to Add Resources to Your Hugo Site

> **Tutorial**: A step-by-step guide to adding new content resources to this Hugo-based cybersecurity blog

## Table of Contents

- [Understanding Hugo Content Structure](#understanding-hugo-content-structure)
- [Adding a New Writeup](#adding-a-new-writeup)
- [Adding a New Maldev Resource](#adding-a-new-maldev-resource)
- [Front Matter Configuration](#front-matter-configuration)
- [Building and Previewing](#building-and-previewing)

---

## Understanding Hugo Content Structure

This site uses Hugo's content organization system. The main content directories are:

```
content/
├── writeups/          # CTF writeups and challenges
│   ├── pwn/          # Binary exploitation
│   ├── web/          # Web security
│   ├── reverse/      # Reverse engineering
│   └── network/      # Network security
└── maldev/           # Malware development resources
```

Each directory can contain:
- `_index.md` - Section index page
- Individual markdown files for articles

---

## Adding a New Writeup

### Step 1: Choose the Right Category

Determine which category your writeup belongs to:
- `pwn` - Binary exploitation
- `web` - Web vulnerabilities
- `reverse` - Reverse engineering
- `network` - Network security
- `crypto` - Cryptography

### Step 2: Create the Markdown File

Create a new file in the appropriate directory:

```bash
# Example: Adding a pwn writeup
touch content/writeups/pwn/2025-10-27-my-challenge.md
```

### Step 3: Add Front Matter

Every markdown file needs front matter (metadata) at the top:

```yaml
---
title: "Challenge Name - CTF Name"
date: 2025-10-27
tags: ["pwn", "buffer-overflow", "exploitation"]
categories: ["pwn"]
ctfs: ["htb"]
---
```

### Step 4: Write Your Content

After the front matter, write your content using Markdown:

```markdown
# Challenge Overview

Description of the challenge...

## Analysis

Your analysis here...

## Solution

Step-by-step solution...
```

---

## Adding a New Maldev Resource

### Step 1: Create the File

Create a new file in the maldev directory:

```bash
touch content/maldev/part3-new-technique.md
```

### Step 2: Add Proper Front Matter

```yaml
---
title: "Part 3: New Technique Name"
date: 2025-10-27
tags: ["maldev", "shellcode", "injection", "security-research"]
---
```

### Step 3: Follow the Established Structure

Use a consistent structure like the existing maldev articles:

```markdown
# Technique Name Guide

> **Educational Notes**: Brief description

## Table of Contents

- [Overview](#overview)
- [Implementation Steps](#implementation-steps)
- [Code Examples](#code-examples)

## Overview

Introduction to the technique...

## Implementation Steps

Detailed steps...

## Code Examples

```cpp
// Your code here
```
```

---

## Front Matter Configuration

### Required Fields

```yaml
---
title: "Your Title Here"        # The page title
date: 2025-10-27                # Publication date (YYYY-MM-DD)
---
```

### Optional Fields

```yaml
tags: ["tag1", "tag2"]          # Tags for filtering and categorization
categories: ["category"]         # Main category
ctfs: ["ctf-name"]              # CTF event name
draft: false                     # Set to true to hide from build
```

### Common Tags

**For Writeups:**
- `pwn`, `web`, `reverse`, `crypto`, `forensics`, `network`
- `buffer-overflow`, `heap-exploitation`, `rop`
- `xss`, `sqli`, `ssrf`
- `binary-analysis`, `decompilation`

**For Maldev:**
- `maldev`, `shellcode`, `injection`, `evasion`
- `process-injection`, `dll-injection`
- `security-research`, `defense`

---

## Building and Previewing

### Local Development Server

Start the Hugo development server to preview your changes:

```bash
hugo server -D
```

This will:
- Start a local web server at `http://localhost:1313`
- Watch for file changes and auto-reload
- Include draft content with the `-D` flag

### Building for Production

Generate the static site files:

```bash
hugo
```

This creates the site in the `public/` directory.

### Common Hugo Commands

```bash
# Start development server
hugo server

# Build site
hugo

# Build with drafts
hugo -D

# Clean generated files
rm -rf public/

# Check Hugo version
hugo version
```

---

## File Naming Conventions

Follow these conventions for consistency:

### Writeups
```
YYYY-MM-DD-challenge-name.md
```
Example: `2024-04-14-breizh-metamorph.md`

### Maldev Resources
```
partN-technique-name.md
```
Example: `part1-shellcode-injector.md`

---

## Tips and Best Practices

1. **Use Descriptive Titles**: Make titles clear and searchable
2. **Add Relevant Tags**: Help users filter content effectively
3. **Include Code Blocks**: Use proper syntax highlighting with language tags
4. **Add Tables of Contents**: For longer articles, include navigation
5. **Use Relative Links**: When linking between pages, use Hugo's `relref`
6. **Optimize Images**: Store images in `static/images/` and reference them
7. **Test Locally**: Always preview with `hugo server` before committing

---

## Example: Complete Writeup Template

```markdown
---
title: "HTB - Challenge Name"
date: 2025-10-27
tags: ["pwn", "buffer-overflow", "rop"]
categories: ["pwn"]
ctfs: ["htb"]
---

# Challenge Name

> **Difficulty**: Medium | **Points**: 100

## Challenge Description

[Description of the challenge]

## Initial Analysis

### File Information

```bash
file challenge
checksec challenge
```

### Running the Binary

[Initial observations]

## Vulnerability Discovery

[Explain the vulnerability]

## Exploitation

### Step 1: Finding the Offset

```python
# Exploit code
```

### Step 2: Building the Payload

[Explanation]

## Solution

```python
# Full exploit
```

## Flag

```
HTB{flag_here}
```

## Lessons Learned

- Key takeaway 1
- Key takeaway 2
```

---

## Getting Help

- Check the [Hugo documentation](https://gohugo.io/documentation/)
- Review existing articles in `content/` for examples
- Test your changes with `hugo server -D`

---
