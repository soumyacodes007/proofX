from __future__ import annotations

import logging

from fastapi import FastAPI

from packageproof.core.config import Settings

logger = logging.getLogger(__name__)


def configure_x402_payments(app: FastAPI, settings: Settings) -> None:
    if not settings.x402_enabled:
        logger.info("x402 middleware disabled by configuration")
        return

    if not settings.payment_configured:
        logger.warning("x402 requested but OKX payment credentials are incomplete")
        return

    try:
        from x402.http import (
            OKXAuthConfig,
            OKXFacilitatorClient,
            OKXFacilitatorConfig,
            PaymentOption,
        )
        from x402.http.middleware.fastapi import PaymentMiddlewareASGI
        from x402.http.types import RouteConfig
        from x402.mechanisms.evm.exact.server import ExactEvmScheme
        from x402.server import x402ResourceServer
    except ImportError as exc:
        logger.warning("x402 SDK unavailable; payment middleware not installed: %s", exc)
        return

    facilitator = OKXFacilitatorClient(
        OKXFacilitatorConfig(
            auth=OKXAuthConfig(
                api_key=settings.okx_api_key,
                secret_key=settings.okx_secret_key,
                passphrase=settings.okx_passphrase,
            ),
            base_url=settings.okx_base_url,
            sync_settle=True,
        )
    )

    server = x402ResourceServer(facilitator)
    server.register(settings.network, ExactEvmScheme())
    routes = {
        "POST /v1/analyze-package": RouteConfig(
            accepts=[
                PaymentOption(
                    scheme="exact",
                    price=settings.analyze_package_price,
                    network=settings.network,
                    pay_to=settings.pay_to_address,
                    max_timeout_seconds=300,
                )
            ],
            description="PackageProof Pro npm/PyPI risk assessment",
            mime_type="application/json",
        )
    }
    app.add_middleware(PaymentMiddlewareASGI, routes=routes, server=server)
    logger.info("x402 middleware enabled for POST /v1/analyze-package")
