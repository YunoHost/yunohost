require ["fileinto"];
if header :is "X-Spam" "yes" {
    fileinto "Junk";
}
