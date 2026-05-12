import httpx
import asyncio
import json

async def test_stream():
    url = "http://localhost:8000/api/stream?file_path=backend/main.py"
    print(f"Connecting to stream: {url}")
    
    async with httpx.AsyncClient(timeout=60) as client:
        try:
            async with client.stream("GET", url) as response:
                print(f"Status: {response.status_code}")
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = json.loads(line[6:])
                        print(f"Event: {data.get('type', 'info')} - {data.get('message', '')[:60]}...")
                        if data.get('type') == 'done':
                            print("Stream finished successfully.")
                            break
        except Exception as e:
            print(f"Stream Failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_stream())
