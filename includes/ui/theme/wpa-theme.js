(function () {
    "use strict";

    document.addEventListener("DOMContentLoaded", function () {
        var config = window.wpauditorTheme;
        var root = document.getElementById("wpaThemeControl");
        var button = document.getElementById("wpaThemeToggle");
        var live = document.getElementById("wpaThemeLive");
        if (!config || !root || !button) return;

        var label = button.querySelector(".wpa-theme-toggle-label");
        var saving = false;
        var currentTheme = config.theme === "light" ? "light" : "dark";

        function applyTheme(theme) {
            var isLight = theme === "light";
            document.body.classList.toggle("wpauditor-theme-light", isLight);
            document.body.classList.toggle("wpauditor-theme-dark", !isLight);
            root.dataset.theme = theme;
            button.setAttribute("aria-checked", isLight ? "true" : "false");
            button.title = isLight ? config.strings.switchToDark : config.strings.switchToLight;
            if (label) label.textContent = isLight ? config.strings.light : config.strings.dark;
        }

        button.addEventListener("click", function () {
            if (saving) return;

            var previousTheme = currentTheme;
            var nextTheme = currentTheme === "dark" ? "light" : "dark";
            var body = new FormData();
            body.set("action", "wpauditor_save_theme");
            body.set("nonce", config.nonce);
            body.set("theme", nextTheme);

            saving = true;
            button.disabled = true;
            root.classList.add("is-saving");
            applyTheme(nextTheme);

            fetch(config.ajaxUrl, {
                method: "POST",
                credentials: "same-origin",
                body: body
            }).then(function (response) {
                if (!response.ok) throw new Error("Theme request failed");
                return response.json();
            }).then(function (json) {
                if (!json || !json.success || !json.data || json.data.theme !== nextTheme) {
                    throw new Error("Invalid theme response");
                }
                currentTheme = nextTheme;
                window.location.reload();
            }).catch(function () {
                applyTheme(previousTheme);
                if (live) live.textContent = config.strings.saveFailed;
                saving = false;
                button.disabled = false;
                root.classList.remove("is-saving");
            });
        });

        applyTheme(currentTheme);
    });
}());
