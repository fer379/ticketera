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

document.querySelectorAll("#flash-messages .alert").forEach((alert) => {
  window.setTimeout(() => {
    if (!alert.isConnected) {
      return;
    }

    if (window.bootstrap && window.bootstrap.Alert) {
      window.bootstrap.Alert.getOrCreateInstance(alert).close();
    } else {
      alert.remove();
    }
  }, 5000);
});

const ticketFilterForm = document.getElementById("ticket-filters");
const ticketResults = document.getElementById("ticket-results");

if (ticketFilterForm && ticketResults) {
  const filterFeedback = document.getElementById("filter-feedback");
  let activeFilterRequest = null;

  function syncFilterControls(url) {
    const params = url.searchParams;
    ticketFilterForm.elements.q.value = params.get("q") || "";
    ticketFilterForm.elements.status.value = params.get("status") || "";
    ticketFilterForm.elements.priority.value = params.get("priority") || "";

    const selectedStatus = params.get("status") || "";
    const selectedPriority = params.get("priority") || "";
    const selectedSearch = params.get("q") || "";
    document.querySelectorAll("[data-status-filter]").forEach((card) => {
      const cardStatus = card.dataset.statusFilter || "";
      const selected = cardStatus
        ? cardStatus === selectedStatus
        : !selectedStatus && !selectedPriority && !selectedSearch;
      card.classList.toggle("is-selected", selected);
      card.setAttribute("aria-current", selected ? "true" : "false");
    });

    const exportLink = document.getElementById("export-csv");
    if (exportLink) {
      const exportUrl = new URL(exportLink.href);
      exportUrl.search = "";
      if (selectedStatus) {
        exportUrl.searchParams.set("status", selectedStatus);
      }
      if (selectedPriority) {
        exportUrl.searchParams.set("priority", selectedPriority);
      }
      exportLink.href = `${exportUrl.pathname}${exportUrl.search}`;
    }
  }

  async function loadTicketResults(targetUrl, updateHistory) {
    if (activeFilterRequest) {
      activeFilterRequest.abort();
    }

    const controller = new AbortController();
    activeFilterRequest = controller;
    ticketResults.setAttribute("aria-busy", "true");
    filterFeedback.classList.add("d-none");

    try {
      const response = await fetch(targetUrl, {
        headers: {
          Accept: "text/html",
          "X-Requested-With": "XMLHttpRequest",
        },
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Filter request failed with status ${response.status}`);
      }

      ticketResults.innerHTML = await response.text();
      const url = new URL(targetUrl, window.location.href);
      syncFilterControls(url);

      if (updateHistory) {
        window.history.pushState({}, "", `${url.pathname}${url.search}`);
      }
    } catch (error) {
      if (error.name === "AbortError") {
        return;
      }

      console.error("No se pudieron actualizar los tickets filtrados.", error);
      filterFeedback.textContent =
        "No se pudo actualizar el listado. Revisá tu conexión e intentá nuevamente.";
      filterFeedback.classList.remove("d-none");
    } finally {
      if (activeFilterRequest === controller) {
        activeFilterRequest = null;
        ticketResults.removeAttribute("aria-busy");
      }
    }
  }

  ticketFilterForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const url = new URL(ticketFilterForm.action, window.location.href);
    const params = new URLSearchParams(new FormData(ticketFilterForm));
    Array.from(params.entries()).forEach(([key, value]) => {
      if (!value.trim()) {
        params.delete(key);
      }
    });
    url.search = params.toString();
    loadTicketResults(url.href, true);
  });

  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) {
      return;
    }

    const filterLink = event.target.closest("a[data-ajax-filter]");
    if (
      !filterLink ||
      event.button !== 0 ||
      event.ctrlKey ||
      event.metaKey ||
      event.shiftKey ||
      event.altKey
    ) {
      return;
    }

    event.preventDefault();
    loadTicketResults(filterLink.href, true);
  });

  window.addEventListener("popstate", () => {
    loadTicketResults(window.location.href, false);
  });
}

const deleteTicketForm = document.getElementById("delete-ticket-form");
const deleteTicketLabel = document.getElementById("delete-ticket-label");
const deleteTicketModal = document.getElementById("deleteTicketModal");
const confirmDeleteButton = document.getElementById("confirm-delete-ticket");

if (
  deleteTicketForm &&
  deleteTicketLabel &&
  deleteTicketModal &&
  confirmDeleteButton
) {
  const fallbackDeleteUrl = deleteTicketForm.action;

  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) {
      return;
    }

    const trigger = event.target.closest(
      'button[data-bs-target="#deleteTicketModal"]'
    );
    if (!trigger) {
      return;
    }

    deleteTicketForm.action = trigger.dataset.deleteUrl || fallbackDeleteUrl;
    deleteTicketLabel.textContent =
      `Ticket #${trigger.dataset.ticketId}: ${trigger.dataset.ticketTitle}`;
    confirmDeleteButton.disabled = !trigger.dataset.deleteUrl;
  });

  deleteTicketModal.addEventListener("hidden.bs.modal", () => {
    deleteTicketForm.action = fallbackDeleteUrl;
    deleteTicketLabel.textContent = "";
    confirmDeleteButton.disabled = true;
  });
}

const sessionCheckUrl = document.body.dataset.sessionCheckUrl;
const sessionCheckFeedback = document.getElementById("session-check-feedback");

if (sessionCheckUrl && sessionCheckFeedback) {
  const sessionCheckInterval =
    Number(document.body.dataset.sessionCheckInterval) * 1000 || 15000;
  const loginUrl = document.body.dataset.loginUrl || "/login";
  let sessionCheckInProgress = false;
  let sessionRedirecting = false;

  async function checkSessionValidity() {
    if (sessionCheckInProgress || sessionRedirecting) {
      return;
    }

    sessionCheckInProgress = true;
    try {
      const response = await fetch(sessionCheckUrl, {
        cache: "no-store",
        headers: { Accept: "application/json" },
      });

      if (response.status === 401) {
        const result = await response.json();
        sessionRedirecting = true;
        window.location.replace(result.redirect || loginUrl);
        return;
      }

      if (!response.ok) {
        throw new Error(`Session validation failed with status ${response.status}`);
      }

      sessionCheckFeedback.classList.add("d-none");
    } catch (error) {
      console.error("No se pudo validar la sesión contra Active Directory.", error);
      sessionCheckFeedback.classList.remove("d-none");
    } finally {
      sessionCheckInProgress = false;
    }
  }

  checkSessionValidity();
  window.setInterval(checkSessionValidity, sessionCheckInterval);
  window.addEventListener("focus", checkSessionValidity);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      checkSessionValidity();
    }
  });
}
