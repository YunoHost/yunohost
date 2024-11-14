require "fileinto"; 
    if header :contains "X-Spam-Flag" "Yes" { 
        fileinto "Junk"; 
    }
