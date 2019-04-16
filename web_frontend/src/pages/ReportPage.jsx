import React, { Component } from "react";
import { Layout, Tabs, Spin } from "antd";

import ReportOverview from "../components/ReportOverview";
import ReportOverviewNetwork from "../components/ReportOverviewNetwork";
import ReportStatic from "../components/ReportStatic";
import ReportDynamic from "../components/ReportDynamic";
import ReportNetwork from "../components/ReportNetwork";

const { Content, Header, Footer } = Layout;
const TabPane = Tabs.TabPane;

class ResultPage extends Component {
  constructor(props) {
    super(props);
    this.state = {
      report: {},
      loaded: false
    };
  }

  componentDidMount() {
    this.loadReport();
  }

  loadReport = () => {
    const id = this.props.match.params.id;
    fetch("http://" + process.env.REACT_APP_HOST + "/api/report/" + id)
      .then(res => res.json())
      .then(report => {
        console.log(report);
        if (!report.hasOwnProperty("error")) {
          this.setState({
            report: report,
            loaded: true
          });
        }
      })
      .catch(error => {
        console.log(error);
      });
  };

  render() {
    const id = this.props.match.params.id;
    const r = this.state.report;

    if (!this.state.loaded) {
      return (
        <div className="report-missing">
          <Spin size="large" />
          <p>
            Can't load your report? <br />
            Check pending and failed tasks..
          </p>
        </div>
      );
    }

    let innerHTML;

    if (r.type === "pcap") {
      innerHTML = (
        <Tabs defaultActiveKey="1" className="tabs-report">
          <TabPane tab="Overview" key="1">
            <div className="inner-pane">
              <ReportOverviewNetwork report={r} id={id} />
            </div>
          </TabPane>

          <TabPane tab="Network Analysis" key="4">
            <div className="inner-pane">
              <ReportNetwork report={r.network_analysis} />
            </div>
          </TabPane>
        </Tabs>
      );
    }

    if (r.type === "binary") {
      innerHTML = (
        <Tabs defaultActiveKey="1" className="tabs-report">
          <TabPane tab="Overview" key="1">
            <div className="inner-pane">
              <ReportOverview report={r} id={id} />
            </div>
          </TabPane>

          <TabPane tab="Static Analysis" key="2">
            <div className="inner-pane">
              <ReportStatic report={r.static_analysis} />
            </div>
          </TabPane>

          <TabPane tab="Dynamic Analysis" key="3">
            <div className="inner-pane">
              <ReportDynamic report={r.dynamic_analysis} />
            </div>
          </TabPane>

          <TabPane tab="Network Analysis" key="4">
            <div className="inner-pane">
              <ReportNetwork report={r.network_analysis} />
            </div>
          </TabPane>
        </Tabs>
      );
    }

    return (
      <Layout style={{ marginLeft: 200 }}>
        <Header className="header">
          <h2 className="header-headline">Analysis report</h2>
        </Header>
        <Content className="page-content">{innerHTML}</Content>
        <Footer className="footer">
          LiSa © 2019 - Created by Daniel Uhricek
        </Footer>
      </Layout>
    );
  }
}

export default ResultPage;
