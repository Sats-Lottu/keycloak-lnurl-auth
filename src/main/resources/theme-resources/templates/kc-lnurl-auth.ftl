<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
  <#if section == "header">
    ${msg("lnurlAuthTitle")}
  <#elseif section == "form">
    <form id="kc-lnurl-auth" method="post" action="${finishUrl}" data-status="${statusUrl}"
          data-expired="${msg('lnurlAuthExpired')}">
      <p>${msg(loopbackWallet?then("lnurlAuthLocalInstructions", "lnurlAuthInstructions"))}</p>
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${qrSize?c} ${qrSize?c}"
           width="248" height="248" role="img" aria-label="${msg('lnurlAuthQr')}" shape-rendering="crispEdges">
        <path fill="#fff" d="M0 0h${qrSize?c}v${qrSize?c}H0z"/>
        <path fill="#111" d="${qrPath}"/>
      </svg>
      <input type="hidden" name="state" value="${brokerState}">
      <input type="hidden" name="ticket" value="${brokerTicket}">
      <#if loopbackWallet>
        <p><button id="kc-lnurl-auth-copy" type="button"
                   class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!}"
                   data-copied="${msg('lnurlAuthCopied')}"
                   data-copy-failed="${msg('lnurlAuthCopyFailed')}">${msg("lnurlAuthCopy")}</button></p>
        <p id="kc-lnurl-auth-copy-status" role="status"></p>
        <p id="kc-lnurl-auth-manual-copy" hidden>
          <label for="kc-lnurl-auth-code">LNURL</label>
          <input id="kc-lnurl-auth-code" type="text" value="${lnurl}" readonly>
        </p>
      <#else>
        <p><a id="kc-lnurl-auth-wallet" class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!}"
              href="lightning:${lnurl}">${msg("lnurlAuthOpen")}</a></p>
      </#if>
      <p role="status" id="kc-lnurl-auth-status" aria-live="polite">${msg("lnurlAuthWaiting")}</p>
      <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}" type="submit">
        ${msg("lnurlAuthContinue")}
      </button>
    </form>
    <p><a href="${url.loginRestartFlowUrl}">${msg("backToLogin")}</a></p>
    <script type="module" src="${url.resourcesPath}/js/kc-lnurl-auth.js"></script>
  </#if>
</@layout.registrationLayout>
