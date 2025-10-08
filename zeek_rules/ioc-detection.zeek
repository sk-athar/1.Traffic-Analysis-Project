##! Custom IOC Detection Script for Malware Traffic Analysis
##! Source: https://www.malware-traffic-analysis.net/2025/01/22/
##!
##! This script detects indicators of compromise from the fake software site malware

@load base/frameworks/notice

module IOC_Detection;

export {
    redef enum Notice::Type += {
        ## Malicious IP detected
        Malicious_IP_Detected,
        
        ## Suspicious URL pattern detected
        Malicious_URL_Detected,
        
        ## Known malicious file hash detected
        Malicious_File_Hash_Detected,
        
        ## Suspicious PowerShell download detected
        PowerShell_Download_Detected,
        
        ## Large data exfiltration detected
        Data_Exfiltration_Detected,
        
        ## Numeric path beacon detected
        Numeric_Beacon_Detected,
    };
}

# Define malicious IPs
global malicious_ips: set[addr] = {
    5.252.153.241,      # Malicious payload server
    45.125.66.32,       # Exfiltration server
    45.125.66.252,      # Additional suspicious IP in range
};

# Define malicious file hashes (MD5)
global malicious_hashes: set[string] = {
    "10febc686b7035ba0731c85e8e474bcd",  # pas.ps1
};

# Define suspicious URL patterns
global suspicious_paths: pattern = 
    /\/1517096937/ |                    # Numeric beacon path
    /\/pas\.ps1/ |                      # PowerShell loader
    /\/29842\.ps1/ |                    # PowerShell payload
    /\/api\/file\/get-file\//;          # File download API pattern

# Define victim host
const victim_host: addr = 10.1.17.215 &redef;

# Track data exfiltration - threshold in bytes (10 MB = 10,000,000)
const exfil_threshold: count = 10000000 &redef;

##
## Event: HTTP Request Detection
##
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    
    # Check for connections to malicious IPs
    if (dst in malicious_ips)
    {
        NOTICE([$note=Malicious_IP_Detected,
                $conn=c,
                $msg=fmt("HTTP request to known malicious IP %s", dst),
                $sub=fmt("URL: %s", original_URI),
                $identifier=cat(src, dst, original_URI)]);
    }
    
    # Check for suspicious URL patterns
    if (suspicious_paths in original_URI)
    {
        NOTICE([$note=Malicious_URL_Detected,
                $conn=c,
                $msg=fmt("Suspicious URL pattern detected: %s", original_URI),
                $sub=fmt("Source: %s -> Destination: %s", src, dst),
                $identifier=cat(src, dst, original_URI)]);
    }
    
    # Check for numeric beacon pattern
    if (/\/[0-9]{10}/ in original_URI)
    {
        NOTICE([$note=Numeric_Beacon_Detected,
                $conn=c,
                $msg=fmt("Numeric path beacon detected: %s", original_URI),
                $sub=fmt("Possible C2 communication from %s to %s", src, dst),
                $identifier=cat(src, dst, original_URI)]);
    }
    
    # Check for PowerShell file downloads
    if (/\.ps1/ in original_URI)
    {
        NOTICE([$note=PowerShell_Download_Detected,
                $conn=c,
                $msg=fmt("PowerShell script download: %s", original_URI),
                $sub=fmt("From %s to %s - High risk!", src, dst),
                $identifier=cat(src, dst, original_URI)]);
    }
}

##
## Event: File Hash Detection
##
event file_hash(f: fa_file, kind: string, hash: string)
{
    if (kind == "md5" && hash in malicious_hashes)
    {
        for (cid in f$conns)
        {
            local c = f$conns[cid];
            NOTICE([$note=Malicious_File_Hash_Detected,
                    $conn=c,
                    $msg=fmt("Known malicious file detected! MD5: %s", hash),
                    $sub=fmt("Filename: %s", f$info$filename),
                    $identifier=hash]);
        }
    }
}

##
## Event: Connection State Removal (end of connection)
## Detect large data transfers (potential exfiltration)
##
event connection_state_remove(c: connection)
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    
    # Check if this is the victim host sending data
    if (src == victim_host && c$orig$size > exfil_threshold)
    {
        NOTICE([$note=Data_Exfiltration_Detected,
                $conn=c,
                $msg=fmt("Large outbound data transfer detected: %s bytes", c$orig$size),
                $sub=fmt("From %s to %s - Possible data exfiltration!", src, dst),
                $identifier=cat(src, dst, c$orig$size)]);
    }
    
    # Also check for connections to known exfil servers
    if (dst in malicious_ips && c$orig$size > 1000000)  # Over 1 MB
    {
        NOTICE([$note=Data_Exfiltration_Detected,
                $conn=c,
                $msg=fmt("Data transfer to malicious IP: %s bytes", c$orig$size),
                $sub=fmt("From %s to %s (known bad IP)", src, dst),
                $identifier=cat(src, dst, c$orig$size)]);
    }
}

##
## Event: DNS Query Detection (optional - detect C2 domains)
##
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    local src = c$id$orig_h;
    
    # You can add domain-based IOCs here if needed
    # Example: if (/malicious\.com/ in query) { ... }
}

print fmt("IOC Detection Script Loaded - Monitoring for indicators from malware-traffic-analysis.net 2025-01-22");
