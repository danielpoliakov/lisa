import React, { Component } from "react";
import { BrowserRouter as Router, Route, Link, Switch } from "react-router-dom";
import { Layout, Menu, Icon } from "antd";

import ReportPage from "./pages/ReportPage";
import ResultsPage from "./pages/ResultsPage";
import FailedTasksPage from "./pages/FailedTasksPage";
import PendingTasksPage from "./pages/PendingTasksPage";
import SubmitPage from "./pages/SubmitPage";
import APIPage from "./pages/APIPage";
import "./App.css";
import logo from "./logo-dark.png";

const { Sider } = Layout;

class App extends Component {
  render() {
    return (
      <Router>
        <Sider id="sider">
          <img src={logo} className="logo" alt="LiSa" />
          <Menu theme="dark" mode="inline" defaultSelectedKeys={["1"]}>
            <Menu.Item key="1">
              <Icon type="appstore" />
              <span className="nav-text">Results</span>
              <Link to="/" />
            </Menu.Item>
            <Menu.Item key="2">
              <Icon type="upload" />
              <span className="nav-text">Submit file</span>
              <Link to="/submit" />
            </Menu.Item>
            <Menu.Item key="3">
              <Icon type="warning" />
              <span className="nav-text">Failed</span>
              <Link to="/failed" />
            </Menu.Item>
            <Menu.Item key="4">
              <Icon type="hourglass" />
              <span className="nav-text">Pending</span>
              <Link to="/pending" />
            </Menu.Item>
            <Menu.Item key="5">
              <Icon type="api" />
              <span className="nav-text">API</span>
              <Link to="/api-doc" />
            </Menu.Item>
          </Menu>
        </Sider>

        <div id="main-content">
          <Switch>
            <Route exact path="/" component={ResultsPage} />
            <Route path="/submit" component={SubmitPage} />
            <Route path="/failed" component={FailedTasksPage} />
            <Route path="/pending" component={PendingTasksPage} />
            <Route path="/result/:id" component={ReportPage} />
            <Route path="/api-doc" component={APIPage} />
          </Switch>
        </div>
      </Router>
    );
  }
}

export default App;
