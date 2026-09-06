"use strict";

document.addEventListener("DOMContentLoaded", () => {
    setupPasswordToggle("password");
    setupPasswordToggle("confirmPassword");
    setupStrengthMeter("password");

    const registerForm = document.getElementById("registrationForm");
    if (registerForm) {
        registerForm.addEventListener("submit", onRegisterSubmit);
    }

    const loginForm = document.getElementById("loginForm");
    if (loginForm) {
        loginForm.addEventListener("submit", onLoginSubmit);
    }
});

// Show/hide a password field when the eye button is clicked.
function setupPasswordToggle(inputId) {
    const toggle = document.querySelector(`[data-toggle="${inputId}"]`);
    const input = document.getElementById(inputId);
    if (!toggle || !input) {
        return;
    }
    toggle.addEventListener("click", () => {
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        toggle.textContent = show ? "🙈" : "👁️";
    });
}

// Live password strength indicator (Weak / Medium / Strong).
function setupStrengthMeter(inputId) {
    const input = document.getElementById(inputId);
    const meter = document.getElementById("passwordStrength");
    if (!input || !meter) {
        return;
    }
    input.addEventListener("input", () => {
        const score = passwordScore(input.value);
        meter.textContent = score.label;
        meter.className = "strength-meter " + score.level;
    });
}

function passwordScore(password) {
    if (password.length < 8) {
        return { label: "Weak", level: "weak" };
    }
    const hasLetter = /[a-zA-Z]/.test(password);
    const hasDigit = /\d/.test(password);
    if (password.length >= 10 && hasLetter && hasDigit && /[^a-zA-Z0-9]/.test(password)) {
        return { label: "Strong", level: "strong" };
    }
    if (hasLetter && hasDigit) {
        return { label: "Medium", level: "medium" };
    }
    return { label: "Weak", level: "weak" };
}

// Client-side checks run before anything is sent to the server.
function validateRegisterForm(fields) {
    const errors = [];
    if (!fields.fullName.trim()) {
        errors.push("Full name is required.");
    }
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(fields.email.trim())) {
        errors.push("Email address looks invalid.");
    }
    if (!/^\d+$/.test(fields.age) || +fields.age < 1 || +fields.age > 120) {
        errors.push("Age must be a number between 1 and 120.");
    }
    if (fields.password.length < 8) {
        errors.push("Password must be at least 8 characters.");
    } else if (!/[a-zA-Z]/.test(fields.password) || !/\d/.test(fields.password)) {
        errors.push("Password must contain at least one letter and one number.");
    }
    if (fields.password !== fields.confirmPassword) {
        errors.push("Passwords do not match.");
    }
    return errors;
}

function showErrors(containerId, errors) {
    const container = document.getElementById(containerId);
    if (!container) {
        return;
    }
    container.innerHTML = "";
    for (const error of errors) {
        const item = document.createElement("div");
        item.className = "error-item";
        item.textContent = error;
        container.appendChild(item);
    }
}

async function onRegisterSubmit(event) {
    event.preventDefault();
    const form = event.target;

    const fields = {
        fullName: form.fullName.value,
        email: form.email.value,
        age: form.age.value,
        password: form.password.value,
        confirmPassword: form.confirmPassword.value,
    };

    const errors = validateRegisterForm(fields);
    if (errors.length > 0) {
        showErrors("registerErrors", errors);
        return;
    }

    const response = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(fields),
    });
    const result = await response.json();
    if (result.ok) {
        window.location.href = "/success";
    } else {
        showErrors("registerErrors", result.errors);
    }
}

async function onLoginSubmit(event) {
    event.preventDefault();
    const form = event.target;

    const response = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            email: form.email.value.trim(),
            password: form.password.value,
        }),
    });
    const result = await response.json();
    if (result.ok) {
        window.location.href = "/dashboard";
    } else {
        showErrors("loginErrors", result.errors);
    }
}