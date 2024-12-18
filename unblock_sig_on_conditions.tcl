when ASM_REQUEST_DONE {
    # Check if the signature ID 200001493 is present, the HTTP path is "user/register" and the Authorization header exists
    if { ([ASM::violation details] contains "sig_data.sig_id 200001493") && ([string tolower [HTTP::path]] eq "/your/path-here") && [HTTP::header exists "Authorization"] } {
        # Log details about the unblocked request
        log local0. "Request unblocked to avoid false positive on ASM violation for XSS signature ID 200001493 for encoded + in bearer token - URI: [HTTP::uri] - ClientIP: [IP::client_addr] - Authorization: [HTTP::header Authorization]"
        
        # Unblock the request
        ASM::unblock
    }
}
