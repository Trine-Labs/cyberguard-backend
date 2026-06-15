import hashlib
from fastapi import Request, Response
from fastapi_cache import FastAPICache

def tenant_key_builder(
    func,
    namespace: str = "",
    request: Request = None,
    response: Response = None,
    *args,
    **kwargs,
):
    """
    Custom cache key builder that includes the current_user's tenant_id.
    This ensures that cached data is strictly isolated per tenant.
    """
    prefix = FastAPICache.get_prefix()
    
    # Extract tenant_id from current_user injected by Depends
    current_user = kwargs.get("current_user")
    tenant_id = "anonymous"
    if current_user and hasattr(current_user, "tenant_id"):
        tenant_id = str(current_user.tenant_id)
        
    # Build cache key with tenant context
    url_path = request.url.path if request else ""
    url_query = request.url.query if request else ""
    
    cache_key = f"{prefix}:{namespace}:{func.__module__}:{func.__name__}:{tenant_id}:{url_path}:{url_query}"
    return hashlib.md5(cache_key.encode()).hexdigest()
