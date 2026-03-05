"""
Solana Meme Token Analyzer - Paid API Server
Charges per-request via x402 micropayment protocol (USDC on Base chain)
"""

import os
import sys
import json
import time
import requests
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Add scripts dir to path so we can import the analyzer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from psdm import MemeAnalyzerPro

app = FastAPI(
    title="Solana Meme Token Analyzer API",
    description="Detect insider wallets and rug risk for any Solana token CA. Pay-per-request via x402.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# ============================================================
# x402 Payment Middleware
# ============================================================
# Price per request in USDC (e.g. 0.02 = $0.02)
PRICE_PER_REQUEST = os.environ.get("PRICE_PER_REQUEST", "0.02")
# Your Base chain wallet address to receive payments
PAY_TO_ADDRESS = os.environ.get("PAY_TO_ADDRESS", "")
# x402 facilitator URL (default: public facilitator)
FACILITATOR_URL = os.environ.get("FACILITATOR_URL", "https://x402.org/facilitator")


def build_402_response():
    """Return HTTP 402 with x402 payment requirements"""
    if not PAY_TO_ADDRESS:
        return None  # x402 not configured, skip payment requirement

    payment_required = {
        "x402Version": 1,
        "accepts": [
            {
                "scheme": "exact",
                "network": "base",
                "maxAmountRequired": str(int(float(PRICE_PER_REQUEST) * 1_000_000)),  # USDC has 6 decimals
                "resource": "/analyze",
                "description": f"Solana meme token risk analysis - ${PRICE_PER_REQUEST} per request",
                "mimeType": "application/json",
                "payTo": PAY_TO_ADDRESS,
                "maxTimeoutSeconds": 60,
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # USDC on Base
                "extra": {
                    "name": "Solana Meme Analyzer",
                    "version": "1.0.0"
                }
            }
        ],
        "error": "Payment required"
    }
    return payment_required


def verify_x402_payment(request: Request) -> bool:
    """Verify incoming x402 payment header"""
    if not PAY_TO_ADDRESS:
        return True  # Payment not configured, allow all requests

    payment_header = request.headers.get("X-PAYMENT")
    if not payment_header:
        return False

    try:
        verify_resp = requests.post(
            f"{FACILITATOR_URL}/verify",
            json={
                "payment": payment_header,
                "paymentRequirements": build_402_response()["accepts"][0]
            },
            timeout=10
        )
        if verify_resp.status_code == 200:
            result = verify_resp.json()
            return result.get("isValid", False)
    except Exception:
        pass
    return False


def settle_x402_payment(payment_header: str) -> dict:
    """Settle the payment with the facilitator"""
    try:
        settle_resp = requests.post(
            f"{FACILITATOR_URL}/settle",
            json={
                "payment": payment_header,
                "paymentRequirements": build_402_response()["accepts"][0]
            },
            timeout=10
        )
        if settle_resp.status_code == 200:
            return settle_resp.json()
    except Exception:
        pass
    return {}


# ============================================================
# API Routes
# ============================================================

@app.get("/")
def root():
    index = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(index):
        return FileResponse(index)
    return {
        "name": "Solana Meme Token Analyzer API",
        "version": "1.0.0",
        "price_per_request": f"${PRICE_PER_REQUEST} USDC",
        "endpoints": {"analyze": "GET /analyze?ca=<TOKEN_CA>"}
    }


@app.get("/health")
def health():
    return {"status": "ok", "payment_configured": bool(PAY_TO_ADDRESS)}


@app.get("/demo")
async def demo(ca: str, request: Request):
    """
    Free endpoint for web UI users (humans).
    No payment required — rate limited by Railway's free tier.
    """
    return await _run_analysis(ca)


async def _run_analysis(ca: str):
    """Shared analysis logic used by both /demo and /analyze"""
    if not ca or len(ca) < 32:
        raise HTTPException(status_code=400, detail="Invalid token CA.")
    try:
        analyzer = MemeAnalyzerPro(ca)
        dex_info = analyzer.get_token_info_dex()
        if not dex_info:
            raise HTTPException(status_code=404, detail="Token not found on DexScreener.")

        # ── DexScreener rich data ──────────────────────────────────────────
        base_token = dex_info.get('baseToken', {})
        symbol      = base_token.get('symbol', '?')
        name        = base_token.get('name', '')
        price       = dex_info.get('priceUsd', '0')
        lp_address  = dex_info.get('pairAddress', '')
        liquidity_usd = dex_info.get('liquidity', {}).get('usd', 0)
        fdv         = dex_info.get('fdv', 0)
        market_cap  = dex_info.get('marketCap', 0)
        dex_id      = dex_info.get('dexId', '')
        price_change = dex_info.get('priceChange', {})
        volume      = dex_info.get('volume', {})
        txns        = dex_info.get('txns', {})

        # Token age
        pair_created_at = dex_info.get('pairCreatedAt')
        age_seconds = 0
        age_str = "unknown"
        if pair_created_at:
            age_seconds = int(time.time()) - pair_created_at // 1000
            if age_seconds < 3600:
                age_str = f"{age_seconds // 60}m"
            elif age_seconds < 86400:
                h = age_seconds // 3600
                m = (age_seconds % 3600) // 60
                age_str = f"{h}h {m}m"
            else:
                d = age_seconds // 86400
                h = (age_seconds % 86400) // 3600
                age_str = f"{d}d {h}h"

        # Social / metadata
        info_block = dex_info.get('info', {})
        image_url = info_block.get('imageUrl', '')
        socials = {}
        for s in info_block.get('socials', []):
            socials[s.get('type', '')] = s.get('url', '')
        websites = [w.get('url', '') for w in info_block.get('websites', [])]

        # ── On-chain holder analysis ───────────────────────────────────────
        total_supply = analyzer.get_token_supply()
        if not total_supply:
            raise HTTPException(status_code=503, detail="Could not fetch token supply.")
        holders = analyzer.get_largest_accounts()
        if not holders:
            raise HTTPException(status_code=503, detail="Could not fetch holder data. Set HELIUS_API_KEY for reliable results.")

        suspicious_count = 0
        top10_share = 0.0
        result_holders = []
        for i, h in enumerate(holders):
            addr   = h['address']
            amount = float(h['uiAmountString'])
            pct    = (amount / total_supply) * 100
            tag    = "normal"
            sol_balance = None
            if addr == lp_address:
                tag = "lp_pool"
            elif i < 12:
                sol_bal = analyzer.get_sol_balance(addr)
                sol_balance = sol_bal if sol_bal != -1 else None
                if i < 10:
                    top10_share += pct
                if sol_bal != -1:
                    if sol_bal < 0.05:
                        tag = "suspected_insider"
                        suspicious_count += 1
                    elif sol_bal > 500:
                        tag = "whale_or_exchange"
            elif i < 10:
                top10_share += pct
            result_holders.append({
                "rank": i + 1,
                "address": addr,
                "percent": round(pct, 2),
                "tag": tag,
                "sol_balance": round(sol_balance, 4) if sol_balance is not None else None,
            })
            time.sleep(0.05)

        # ── Risk scoring 0–100 ────────────────────────────────────────────
        risk_score = 0
        warnings = []

        # Insider wallets
        if suspicious_count >= 5:
            risk_score += 35
        elif suspicious_count >= 3:
            risk_score += 25
        elif suspicious_count >= 1:
            risk_score += 15
        if suspicious_count > 0:
            warnings.append(f"Detected {suspicious_count} suspected insider wallet(s) — SOL balance < 0.05")

        # Concentration
        if top10_share > 50:
            risk_score += 30
            warnings.append(f"Extreme concentration: top 10 hold {top10_share:.1f}%")
        elif top10_share > 30:
            risk_score += 15
            warnings.append(f"High concentration: top 10 hold {top10_share:.1f}%")

        # Liquidity depth
        if liquidity_usd and liquidity_usd < 5_000:
            risk_score += 20
            warnings.append(f"Critically low liquidity: ${liquidity_usd:,.0f}")
        elif liquidity_usd and liquidity_usd < 20_000:
            risk_score += 10
            warnings.append(f"Low liquidity: ${liquidity_usd:,.0f}")

        # Token age
        if age_seconds > 0:
            if age_seconds < 3600:
                risk_score += 15
                warnings.append(f"Very new token — only {age_str} old")
            elif age_seconds < 86400:
                risk_score += 5

        # Sell pressure (1h txns)
        h1_txns = txns.get('h1', {})
        h1_buys  = h1_txns.get('buys', 0)
        h1_sells = h1_txns.get('sells', 0)
        if h1_buys + h1_sells > 0:
            sell_ratio = h1_sells / (h1_buys + h1_sells)
            if sell_ratio > 0.70:
                risk_score += 10
                warnings.append(f"Heavy sell pressure last 1h: {sell_ratio*100:.0f}% sells")

        risk_score = min(risk_score, 100)
        if risk_score >= 80:
            risk_level = "EXTREME"
        elif risk_score >= 55:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "token": {
                "ca": ca,
                "symbol": symbol,
                "name": name,
                "price_usd": price,
                "price_change": price_change,
                "market_cap": market_cap,
                "fdv": fdv,
                "liquidity_usd": liquidity_usd,
                "volume": volume,
                "txns": txns,
                "age_str": age_str,
                "age_seconds": age_seconds,
                "dex": dex_id,
                "pair_address": lp_address,
                "image_url": image_url,
                "socials": socials,
                "websites": websites,
            },
            "risk": {
                "score": risk_score,
                "level": risk_level,
                "top10_concentration_pct": round(top10_share, 2),
                "suspected_insider_count": suspicious_count,
                "warnings": warnings,
            },
            "holders": result_holders,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/analyze")
async def analyze(ca: str, request: Request):
    """
    Analyze a Solana token CA for rug risk.
    Requires x402 micropayment of ${PRICE_PER_REQUEST} USDC on Base chain.
    
    Parameters:
        ca: Solana token contract address
    
    Returns:
        token info, risk level, holder analysis, warnings
    """
    if not ca or len(ca) < 32:
        raise HTTPException(status_code=400, detail="Invalid token CA. Must be a valid Solana address.")

    # Check x402 payment
    if PAY_TO_ADDRESS:
        payment_header = request.headers.get("X-PAYMENT")

        if not payment_header:
            payment_required = build_402_response()
            return Response(
                content=json.dumps(payment_required),
                status_code=402,
                headers={
                    "Content-Type": "application/json",
                    "Access-Control-Expose-Headers": "X-PAYMENT-RESPONSE"
                }
            )

        if not verify_x402_payment(request):
            raise HTTPException(status_code=402, detail="Invalid or expired payment")

    # Run analysis and settle payment
    result = await _run_analysis(ca)

    if PAY_TO_ADDRESS:
        payment_header = request.headers.get("X-PAYMENT")
        if payment_header:
            settlement = settle_x402_payment(payment_header)
            return Response(
                content=json.dumps(result),
                status_code=200,
                headers={
                    "Content-Type": "application/json",
                    "X-PAYMENT-RESPONSE": json.dumps(settlement)
                }
            )
    return result


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
