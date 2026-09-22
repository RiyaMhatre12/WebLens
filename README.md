document.addEventListener("DOMContentLoaded", () => {

    const scanBtn =
        document.getElementById("scanBtn");

    const scoreElement =
        document.getElementById("score");

    const riskElement =
        document.getElementById("riskLevel");

    const securityResults =
        document.getElementById("securityResults");

    const formResults =
        document.getElementById("formResults");

    const urlResults =
        document.getElementById("urlResults");

    const resourceResults =
        document.getElementById("resourceResults");

    const statusElement =
        document.getElementById("status");


    /* =====================================
       SCAN BUTTON
    ===================================== */

    scanBtn.addEventListener("click", async () => {

        try {

            scanBtn.disabled = true;

            scanBtn.textContent =
                "⏳ Scanning...";

            statusElement.textContent =
                "Analyzing current webpage...";


            /* =================================
               GET ACTIVE TAB
            ================================= */

            const tabs =
                await chrome.tabs.query({
                    active: true,
                    currentWindow: true
                });


            if (!tabs || !tabs.length) {

                throw new Error(
                    "No active tab found."
                );

            }


            const tab =
                tabs[0];


            /* =================================
               RESTRICTED CHROME PAGES
            ================================= */

            if (
                !tab.id ||
                !tab.url ||
                tab.url.startsWith("chrome://") ||
                tab.url.startsWith("edge://") ||
                tab.url.startsWith("about:") ||
                tab.url.startsWith("chrome-extension://")
            ) {

                throw new Error(
                    "This page cannot be scanned."
                );

            }


            /* =================================
               EXECUTE PAGE ANALYSIS
            ================================= */

            const results =
                await chrome.scripting.executeScript({

                    target: {
                        tabId: tab.id
                    },

                    func: analyzePage

                });


            if (
                !results ||
                !results.length ||
                !results[0].result
            ) {

                throw new Error(
                    "Unable to analyze this page."
                );

            }


            const data =
                results[0].result;


            /* =================================
               CALCULATE SCORE
            ================================= */

            const score =
                calculateSecurityScore(data);


            /* =================================
               DISPLAY SCORE
            ================================= */

            displayScore(
                score,
                scoreElement,
                riskElement
            );


            /* =================================
               DISPLAY SECURITY CHECKS
            ================================= */

            displaySecurityChecks(
                data,
                securityResults
            );


            /* =================================
               DISPLAY FORMS
            ================================= */

            displayForms(
                data,
                formResults
            );


            /* =================================
               DISPLAY URL
            ================================= */

            displayURL(
                data,
                urlResults
            );


            /* =================================
               DISPLAY RESOURCES
            ================================= */

            displayResources(
                data,
                resourceResults
            );


            statusElement.textContent =
                "Scan completed successfully.";


        } catch (error) {

            console.error(
                "WebLens Sentinel Error:",
                error
            );


            scoreElement.textContent =
                "--";


            riskElement.textContent =
                "Scan failed";


            securityResults.innerHTML = `
                <p class="muted">
                    Unable to scan this page.
                </p>
            `;


            formResults.innerHTML = `
                <p class="muted">
                    No scan performed.
                </p>
            `;


            urlResults.innerHTML = `
                <p class="muted">
                    No URL analysis performed.
                </p>
            `;


            resourceResults.innerHTML = `
                <p class="muted">
                    No scan performed.
                </p>
            `;


            statusElement.textContent =
                error.message;


        } finally {

            scanBtn.disabled = false;

            scanBtn.textContent =
                "🔍  Run Security Scan";

        }

    });

});


/* =========================================
   PAGE ANALYSIS
========================================= */

function analyzePage() {

    const forms =
        Array.from(
            document.querySelectorAll("form")
        );


    const inputs =
        Array.from(
            document.querySelectorAll(
                "input"
            )
        );


    const passwordInputs =
        inputs.filter(
            input =>
                input.type === "password"
        );


    const scripts =
        Array.from(
            document.querySelectorAll(
                "script[src]"
            )
        );


    const links =
        Array.from(
            document.querySelectorAll(
                "a[href]"
            )
        );


    const iframes =
        Array.from(
            document.querySelectorAll(
                "iframe"
            )
        );


    const images =
        Array.from(
            document.querySelectorAll(
                "img[src]"
            )
        );


    const stylesheets =
        Array.from(
            document.querySelectorAll(
                'link[rel="stylesheet"]'
            )
        );


    const currentURL =
        window.location.href;


    const pageProtocol =
        window.location.protocol;


    const hostname =
        window.location.hostname;


    /* =====================================
       EXTERNAL SCRIPTS
    ===================================== */

    const externalScripts =
        scripts.filter(script => {

            try {

                const url =
                    new URL(
                        script.src,
                        window.location.href
                    );

                return (
                    url.hostname !== hostname
                );

            } catch {

                return false;

            }

        });


    /* =====================================
       EXTERNAL LINKS
    ===================================== */

    const externalLinks =
        links.filter(link => {

            try {

                const url =
                    new URL(
                        link.href,
                        window.location.href
                    );

                return (
                    url.protocol.startsWith("http") &&
                    url.hostname !== hostname
                );

            } catch {

                return false;

            }

        });


    /* =====================================
       MIXED CONTENT
    ===================================== */

    let mixedContent = 0;


    if (pageProtocol === "https:") {

        const resources = [

            ...scripts.map(
                script => script.src
            ),

            ...images.map(
                image => image.src
            ),

            ...stylesheets.map(
                stylesheet => stylesheet.href
            ),

            ...Array.from(
                document.querySelectorAll(
                    "[src]"
                )
            ).map(
                element => element.src
            )

        ];


        mixedContent =
            resources.filter(
                resource =>
                    typeof resource === "string" &&
                    resource.startsWith("http:")
            ).length;

    }


    /* =====================================
       PASSWORD FORM SECURITY
    ===================================== */

    const passwordForms =
        forms.filter(form =>
            form.querySelector(
                'input[type="password"]'
            )
        );


    /* =====================================
       RETURN DATA
    ===================================== */

    return {

        url: currentURL,

        protocol: pageProtocol,

        hostname: hostname,

        isHTTPS:
            pageProtocol === "https:",

        forms:
            forms.length,

        passwordFields:
            passwordInputs.length,

        passwordForms:
            passwordForms.length,

        scripts:
            scripts.length,

        externalScripts:
            externalScripts.length,

        links:
            links.length,

        externalLinks:
            externalLinks.length,

        iframes:
            iframes.length,

        mixedContent:
            mixedContent,

        images:
            images.length,

        stylesheets:
            stylesheets.length

    };

}


/* =========================================
   SECURITY SCORE
========================================= */

function calculateSecurityScore(data) {

    let score = 100;


    /* HTTPS */

    if (!data.isHTTPS) {

        score -= 30;

    }


    /* Mixed Content */

    score -=
        Math.min(
            data.mixedContent * 10,
            20
        );


    /* Password fields on insecure page */

    if (
        !data.isHTTPS &&
        data.passwordFields > 0
    ) {

        score -= 20;

    }


    /* External scripts */

    score -=
        Math.min(
            data.externalScripts * 3,
            15
        );


    /* Iframes */

    score -=
        Math.min(
            data.iframes * 2,
            10
        );


    /* Keep score within range */

    score =
        Math.max(
            0,
            Math.min(
                100,
                score
            )
        );


    return score;

}


/* =========================================
   DISPLAY SCORE
========================================= */

function displayScore(
    score,
    scoreElement,
    riskElement
) {

    scoreElement.textContent =
        `${score}/100`;


    if (score >= 80) {

        scoreElement.className =
            "safe";

        riskElement.textContent =
            "● Low Risk";

        riskElement.className =
            "safe";

    } else if (score >= 50) {

        scoreElement.className =
            "warning";

        riskElement.textContent =
            "● Medium Risk";

        riskElement.className =
            "warning";

    } else {

        scoreElement.className =
            "danger";

        riskElement.textContent =
            "● High Risk";

        riskElement.className =
            "danger";

    }

}


/* =========================================
   SECURITY CHECKS
========================================= */

function displaySecurityChecks(
    data,
    container
) {

    const httpsStatus =
        data.isHTTPS
            ? `<strong class="safe">✓ Enabled</strong>`
            : `<strong class="danger">✕ Not Enabled</strong>`;


    const mixedStatus =
        data.mixedContent === 0
            ? `<strong class="safe">✓ None</strong>`
            : `<strong class="danger">${data.mixedContent}</strong>`;


    container.innerHTML = `

        <div class="result">
            <span>HTTPS</span>
            ${httpsStatus}
        </div>

        <div class="result">
            <span>Mixed Content</span>
            ${mixedStatus}
        </div>

        <div class="result">
            <span>External Scripts</span>
            <strong>${data.externalScripts}</strong>
        </div>

        <div class="result">
            <span>External Links</span>
            <strong>${data.externalLinks}</strong>
        </div>

        <div class="result">
            <span>iFrames</span>
            <strong>${data.iframes}</strong>
        </div>

    `;

}


/* =========================================
   FORMS
========================================= */

function displayForms(
    data,
    container
) {

    const passwordStatus =
        data.passwordFields > 0
            ? `<strong class="warning">⚠ ${data.passwordFields}</strong>`
            : `<strong class="safe">✓ 0</strong>`;


    container.innerHTML = `

        <div class="result">
            <span>Total Forms</span>
            <strong>${data.forms}</strong>
        </div>

        <div class="result">
            <span>Password Fields</span>
            ${passwordStatus}
        </div>

    `;

}


/* =========================================
   URL ANALYSIS
========================================= */

function displayURL(
    data,
    container
) {

    const protocolStatus =
        data.isHTTPS
            ? `<strong class="safe">✓ HTTPS</strong>`
            : `<strong class="danger">✕ HTTP</strong>`;


    container.innerHTML = `

        <div class="url-indicator">
            <span>Protocol</span>
            ${protocolStatus}
        </div>

        <div class="url-indicator">
            <span>Hostname</span>
            <strong>${escapeHTML(
                data.hostname
            )}</strong>
        </div>

    `;

}


/* =========================================
   EXTERNAL RESOURCES
========================================= */

function displayResources(
    data,
    container
) {

    container.innerHTML = `

        <div class="result">
            <span>Scripts</span>
            <strong>${data.scripts}</strong>
        </div>

        <div class="result">
            <span>Images</span>
            <strong>${data.images}</strong>
        </div>

        <div class="result">
            <span>Stylesheets</span>
            <strong>${data.stylesheets}</strong>
        </div>

        <div class="result">
            <span>External Scripts</span>
            <strong>${data.externalScripts}</strong>
        </div>

    `;

}


/* =========================================
   HTML ESCAPE
========================================= */

function escapeHTML(value) {

    return String(value)

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );

}
