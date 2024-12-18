when ASM_REQUEST_DONE {
    # Check if the signature ID 200001493 is present, the HTTP path is "user/register",
    # and the Authorization header exists
    if { ([ASM::violation details] contains "sig_data.sig_id 200001493") && ([string tolower [HTTP::path]] eq "/user/register") && [HTTP::header exists "Authorization"] } {
        # Log details about the unblocked request
        log local0. "Request unblocked - URI: [HTTP::uri] - ClientIP: [IP::client_addr] - Authorization: [HTTP::header Authorization]"
        
        # Unblock the request
        ASM::unblock
    }
}
