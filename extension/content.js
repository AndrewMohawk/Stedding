chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    const validEntries = request.validEntries;
    const currentURL = window.location.href;

    if (!validEntries.includes(currentURL)) {
        // Add a banner to the page
        const banner = document.createElement('div');
        banner.style.position = 'fixed';
        banner.style.top = '0';
        banner.style.width = '100%';
        banner.style.backgroundColor = 'red';
        banner.textContent = 'The wallet has been unloaded';
        document.body.prepend(banner);
        
        // Unload the wallet
        window.ethereum = null;
    }
});