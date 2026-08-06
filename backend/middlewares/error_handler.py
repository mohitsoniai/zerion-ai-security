from fastapi import Request, Response
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from utils.logger import error_logger

class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """
    Central Exception Handler middleware to intercept unhandled application errors 
    and provide structured, developer-friendly responses.
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        try:
            return await call_next(request)
        except Exception as exc:
            error_logger.error(f"Unhandled exception encountered during request: {request.url.path}", exc)
            return JSONResponse(
                status_code=500,
                content={
                    "error": "InternalServerError",
                    "message": "An unexpected error occurred while processing your request.",
                    "details": str(exc)
                }
            )

async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Formats validation errors (Pydantic / body fields) into readable responses."""
    errors = []
    for error in exc.errors():
        field = ".".join(map(str, error.get("loc", [])))
        msg = error.get("msg", "Validation failed")
        errors.append({"field": field, "issue": msg})
        
    error_logger.warn(f"Request validation failed on path: {request.url.path}", errors=errors)
    return JSONResponse(
        status_code=422,
        content={
            "error": "ValidationError",
            "message": "The request body failed parameter constraints validation.",
            "errors": errors
        }
    )

async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Formats standard HTTP Exceptions into unified API errors."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.__class__.__name__,
            "message": exc.detail
        }
    )
