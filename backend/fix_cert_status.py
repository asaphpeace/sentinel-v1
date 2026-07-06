"""
One-time fix: rename status='healthy' -> 'ok' in ssl_certs.
Run once: python fix_cert_status.py
"""
import asyncio
from sqlalchemy import text
from app.database import AsyncSessionLocal

async def main():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("UPDATE ssl_certs SET status = 'ok' WHERE status = 'healthy'")
        )
        await db.commit()
        print(f"Updated {result.rowcount} row(s).")

asyncio.run(main())
