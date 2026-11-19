"use strict";

const passwordInput = document.getElementById("password");
const togglePassword = document.getElementById("toggle-password");

if (passwordInput && togglePassword) {
  togglePassword.addEventListener("click", () => {
    const showPassword = passwordInput.type === "password";
    passwordInput.type = showPassword ? "text" : "password";
    togglePassword.textContent = showPassword ? "Ocultar" : "Mostrar";
    togglePassword.setAttribute("aria-pressed", String(showPassword));
    togglePassword.setAttribute(
      "aria-label",
      showPassword ? "Ocultar contraseña" : "Mostrar contraseña"
    );
  });
}
