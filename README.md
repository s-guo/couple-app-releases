# Couple Stuff release feed

Public TestFlight release infrastructure for Couple Stuff. The iOS app source and relationship data are not stored here.

Feed: https://s-guo.github.io/couple-app-releases/release.json

## Activate automatic release checks

The workflow is initially configured to publish a disabled feed. This lets the app check the URL without requiring an update before Apple access is configured.

1. An Apple Account Holder/Admin creates a team App Store Connect API key that can read this app and its TestFlight builds/groups.
2. Add these **Actions repository secrets** at https://github.com/s-guo/couple-app-releases/settings/secrets/actions:
   - `ASC_KEY_ID`: key ID.
   - `ASC_ISSUER_ID`: team issuer ID.
   - `ASC_PRIVATE_KEY`: the complete `.p8` file, including BEGIN/END lines and real newlines. Never commit the file.
3. Set the Actions repository variable `REQUIRE_LATEST_BUILD` to `true` at https://github.com/s-guo/couple-app-releases/settings/variables/actions.
4. Run **Actions → Publish TestFlight release feed → Run workflow**. Confirm it succeeds and inspect `release.json`. Only processed, unexpired iOS builds available for the configured tester group are announced. If no eligible build exists, the feed stays disabled.

Other configured variables are `ASC_APP_ID`, `ASC_BETA_GROUP`, `APP_BUNDLE_ID`, and `RELEASE_FEED_ENABLED=true`. Pages uses GitHub Actions. The workflow runs approximately every 15 minutes and can also be run manually.

To withdraw an update requirement, set `REQUIRE_LATEST_BUILD=false` and run the workflow. This works without a valid Apple key. To stop all publishing, set `RELEASE_FEED_ENABLED=false`; cached requirements in the app expire within 24 hours.

The feed contains only bundle/version/build metadata, timestamps, and a public App Store ID. Credentials exist only as Actions secrets. The app source repository keeps the canonical publisher, tests, and workflow; copy those three files here when updating release infrastructure.

## Verify publisher changes

```sh
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```
