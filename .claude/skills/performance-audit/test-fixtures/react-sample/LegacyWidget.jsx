import React from "react";

// PLANTED LANE 5 #A (deprecated lifecycle): `componentWillReceiveProps` is a legacy/unsafe
// lifecycle. The currency brief flags it (deprecated since React 16.3; only `UNSAFE_`-prefixed
// aliases remain) in favor of `getDerivedStateFromProps` or function components + hooks. The code
// works today — it's a stale, at-risk idiom identifiable only via the brief.
export class LegacyWidget extends React.Component {
  state = { value: this.props.value };

  componentWillReceiveProps(nextProps) {
    this.setState({ value: nextProps.value });
  }

  render() {
    return <span>{this.state.value}</span>;
  }
}
