import httpx
import asyncio
import sys

async def test_health():
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get("http://localhost:8000/health")
            print(f"Health Check: {response.status_code} - {response.json()}")
        except Exception as e:
            print(f"Health Check Failed: {e}")

async def test_auth_init():
    async with httpx.AsyncClient() as client:
        try:
            # We don't follow redirects because it goes to GitHub
            response = await client.get("http://localhost:8000/api/auth/github", follow_redirects=False)
            print(f"Auth Init: {response.status_code}")
            if response.status_code == 307:
                print(f"Redirect Location: {response.headers.get('location')}")
        except Exception as e:
            print(f"Auth Init Failed: {e}")

async def main():
    print("--- Starting Backend Logic Tests ---")
    await test_health()
    await test_auth_init()
    print("--- Tests Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
