---
title: Contributing to Documentation
post_excerpt: Learn how to suggest edits and improvements to ExpressTrack documentation through GitHub. Includes file formatting, markdown guidelines, and submission process.
menu_order: 98
---

# Contributing to Documentation

ExpressTrack documentation is hosted on GitHub and automatically synced to our website. You can suggest edits, improvements, or report issues directly through GitHub.

## Quick Edit Process

1. **Find the "Edit this page" link** at the bottom of any documentation page
2. **Click the link** to open the corresponding file on GitHub
3. **Make your changes** using GitHub's web editor
4. **Submit a pull request** with your proposed changes

## File Structure and Format

Documentation files are written in Markdown (`.md`) and organized in folders that mirror the website structure.

### File Naming

* Use lowercase with hyphens: `api-reference.md`
* Avoid spaces and special characters
* Repository root maps to `/docs/` on the site
* File names become URL slugs (e.g., `getting-started.md` → `https://expresstrack.net/docs/getting-started/`)
* Directory structure mirrors website URLs (e.g., `api/webhooks.md` → `https://expresstrack.net/docs/api/webhooks/`)
* Each directory creates a section page using its `index.md` file

### Front Matter Properties

Add metadata at the top of files between `---` lines:
![](/_images/frontmatter.png)

**Key properties:**

* `title` – Page title (required)
* `post_excerpt` – Brief description for SEO
* `menu_order` - Sort order of the document among its siblings

## Content Guidelines

### Images

* Place all images in the `_images` folder
* Reference with: `![Alt text](/_images/filename.jpg "Caption")`
* Use descriptive filenames and alt text

### Links

* **Internal links:** Use relative paths to other markdown files

  * Same directory: `[Link text](./other-page.md)`
  * Parent directory: `[Link text](../guide/setup.md)`
  * Root directory: `[Link text](/api/reference.md)`

* **External links:** Use full URLs with `https://`

### Code Examples

Use fenced code blocks with language specification:

![](/_images/fenced_code_block.png)

## Types of Contributions

### Documentation Improvements

* Fix typos, grammar, or unclear explanations
* Add missing code examples
* Improve API endpoint documentation
* Update outdated information

### New Content

* Tutorial guides for common use cases
* Integration examples for popular platforms
* FAQ entries based on support questions

## Submission Process

1. **Fork the repository** (for substantial changes)

2. **Create a descriptive branch name** like `fix-webhook-docs` or `add-php-example`

3. **Make your changes** following the format guidelines above

4. **Test links and formatting** by previewing in GitHub

5. **Submit a pull request** with:

   * Clear description of changes
   * Reason for the change
   * Any related issue numbers

## Review and Publishing

* All changes are reviewed before merging
* Once approved, changes automatically sync to the website within a few minutes
* You'll receive notification when your contribution is published

## Getting Help

* **GitHub Issues:** Report bugs or request new documentation

Thank you for helping improve ExpressTrack's documentation. Clear, accurate docs benefit the entire developer community.