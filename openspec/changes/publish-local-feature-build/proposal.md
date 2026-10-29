# Publish the local feature build

## Why

The deployed local feature line is absent from the shared fork. Another developer
needs all of its source, local migrations, and setup requirements.

## What Changes

Publish the installed source as a dedicated branch, preserve its application
behavior, remove deployment-specific notes before publication, document setup,
and cover the measured-quota fix with selection-level regression tests.

## Impact

This publishes a source branch. It does not merge newer upstream main, deploy to
another computer, or release a package. Private credentials and installation
state remain local.
