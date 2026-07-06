"""
Shared async DNS resolver that uses public nameservers with caching disabled.

Caching is intentionally off so that DNS checks always reflect the live state
of a record — important when a user has just published a new record and clicks
Regenerate to confirm it was picked up.
"""
import dns.asyncresolver
import dns.resolver

resolver = dns.asyncresolver.Resolver()
resolver.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "1.0.0.1"]
resolver.timeout = 5
resolver.lifetime = 10
resolver.cache = None
