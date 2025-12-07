# CLR-Unhook
Modern security products (CrowdStrike, Bitdefender, SentinelOne, etc.) hook the nLoadImage function inside clr.dll to intercept and scan in-memory .NET assembly loads. This tool unhooks that function. 
