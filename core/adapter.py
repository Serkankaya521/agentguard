import asyncio
from typing import Dict, Any, Optional
import litellm

class LiveModelAdapter:
    """
    LiteLLM tabanlı asenkron model iletişim adaptörü.
    Ücretsiz API kotalarını aşmamak için rate-limit ve retry desteği içerir.
    """
    def __init__(
        self,
        model_name: str = "gemini/gemini-3.6-flash",
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        timeout_seconds: float = 30.0,
        delay_between_calls: float = 4.0 # Ücretsiz kota için istekler arası bekleme
    ):
        self.model_name = model_name
        self.api_key = api_key
        self.api_base = api_base
        self.timeout_seconds = timeout_seconds
        self.delay_between_calls = delay_between_calls
        self._lock = asyncio.Lock()

    async def execute_prompt(self, prompt: str) -> str:
        """Tek bir promptu kota dostu şekilde gönderir ve yanıtı döner."""
        async with self._lock:
            # İstekler arasına kontrollü nefes alma süresi koyuyoruz
            await asyncio.sleep(self.delay_between_calls)

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = await litellm.acompletion(
                    model=self.model_name,
                    messages=[{"role": "user", "content": prompt}],
                    api_key=self.api_key,
                    api_base=self.api_base,
                    timeout=self.timeout_seconds
                )
                content = response.choices[0].message.content or ""
                return content
            except Exception as e:
                err_str = str(e)
                if "429" in err_str or "RateLimitError" in err_str:
                    wait_time = 15 * (attempt + 1)
                    print(f"\n[!] Rate-Limit algılandı. {wait_time} saniye bekleniyor (Deneme {attempt+1}/{max_retries})...")
                    await asyncio.sleep(wait_time)
                else:
                    return f"[ADAPTER_ERROR]: {err_str}"
        
        return "[ADAPTER_ERROR]: Maximum retry limit exceeded due to rate limits."