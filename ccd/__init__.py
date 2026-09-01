"""Contacts & calendar downloader.

A single-host HTTP service that links Google and Microsoft accounts over
OAuth 2.0 and publishes each linked account's contacts and calendar at a
stable secret URL. Tokens live in one 0600 JSON file per account under the
config directory and go nowhere except the provider's own endpoints.
"""

__version__ = "3.0.0"
