# Hosted MCP connector checks

These checks require a person and a disposable MCP endpoint with a harmless echo tool. Keep the publisher running and use the printed Connector URL. Record the date, client and version, connector URL (without credentials), sign-in and consent results, visible tools, echo result, errors, and removal result. Do not record tokens or authorization codes.

## Claude.ai web — unverified

1. Sign in to Claude.ai in a browser. Open Settings, then Connectors, and choose Add custom connector. Enter a recognizable test name and the Connector URL.
2. Start the connection, sign in to tunn as the allowed account, and approve the requested access. Record the result and any error.
3. In a new conversation enable the connector, ask Claude to list its tools and call the harmless echo tool with a test message. Record the tool name and returned message.
4. Return to Settings > Connectors and remove the test connector. In tunn open `/account/mcp` and disconnect its authorization. Record both removals.

## Claude phone app — unverified

1. Sign in to the phone app with the test account. In Settings > Connectors add the custom connector using the same Connector URL, if the app offers that action. Otherwise add it on Claude.ai web and record that the app could not add it.
2. Connect and complete tunn sign-in and consent on the phone. Record the app version and the result.
3. Start a conversation, enable the connector, list the tools and call the harmless echo tool. Record the result and any error.
4. Remove the connector in Settings > Connectors; if removal is unavailable on the phone, remove it on the web and record that limitation. Disconnect its authorization at tunn `/account/mcp`.

## ChatGPT — unverified

1. Sign in to ChatGPT. Open Settings > Apps > Advanced settings and enable developer mode if available. Under Apps choose Create, enter a test name and the Connector URL, and select OAuth. Save the app.
2. Connect it, sign in to tunn as the allowed account and approve access. Record the result and any error.
3. In a new chat select the app from the tools menu, ask to list its tools and call the harmless echo tool. Record the tool and returned message.
4. Open Settings > Apps, disconnect and delete the test app, then disconnect its authorization at tunn `/account/mcp`. Record both removals.

The labels and availability can vary by account and client version; record any difference instead of marking a step passed without doing it.

## Local protocol check and callback reference

Run `make test-mcp-clients` with the scratch SDK and browser paths described in
[scripts/integration-tests/mcp-real-clients/README.md](../../scripts/integration-tests/mcp-real-clients/README.md).
It checks official TypeScript and Python SDK OAuth on loopback and writes
`clients.json` plus consent screenshots outside the checkout. It does not verify
any of the three hosted clients above.

The scripted replay treats `https://claude.ai/api/mcp/auth_callback` and
`https://claude.com/api/mcp/auth_callback` as exact registered identifiers. For
ChatGPT it replays `https://chatgpt.com/connector_platform_oauth_redirect`, the
stable callback documented in [OpenAI's authentication guide](https://developers.openai.com/plugins/build/auth).
That guide also documents a connection-specific `/connector/oauth/{callback_id}`
callback when issuer identification requirements are unmet. For a live check,
copy the exact redirect shown on the app's management page; do not infer it from
the synthetic replay. Save the callback shown, the client version and the date
alongside the manual results, without codes or tokens.
