const form = document.querySelector("#kc-lnurl-auth");
const status = document.querySelector("#kc-lnurl-auth-status");
const copy = document.querySelector("#kc-lnurl-auth-copy");
const deadline = Date.now() + 180_000;
let submitting = false;

copy?.addEventListener("click", async () => {
    const code = document.querySelector("#kc-lnurl-auth-code");
    const copyStatus = document.querySelector("#kc-lnurl-auth-copy-status");

    try {
        await navigator.clipboard.writeText(code.value);
        copyStatus.textContent = copy.dataset.copied;
    } catch {
        copyStatus.textContent = copy.dataset.copyFailed;
        document.querySelector("#kc-lnurl-auth-manual-copy").hidden = false;
        code.focus();
        code.select();
    }
});

form.addEventListener("submit", event => {
    if (submitting) {
        event.preventDefault();
        return;
    }
    submitting = true;
});

async function poll() {
    if (submitting) return;
    if (Date.now() >= deadline) {
        status.textContent = form.dataset.expired;
        for (const button of form.querySelectorAll("button")) button.disabled = true;
        return;
    }

    try {
        const response = await fetch(form.dataset.status, {
            method: "POST",
            body: new URLSearchParams({ticket: form.elements.ticket.value}),
            cache: "no-store",
            redirect: "error",
            signal: AbortSignal.timeout(5000),
        });
        if (response.status === 204) {
            if (!submitting) form.requestSubmit();
            return;
        }
    } catch {
        // A wallet approval can still arrive after a temporary network failure.
    }
    setTimeout(poll, 1500);
}

setTimeout(poll, 1500);
