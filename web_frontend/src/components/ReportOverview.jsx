import React, { Component } from "react";
import { Table, Button } from "antd";

const columnsOverview = [
  {
    title: "Key",
    dataIndex: "key",
    render: text => <b>{text}</b>,
    width: 150
  },
  {
    title: "Value",
    dataIndex: "value"
  }
];

const columnsAnomalies = [
  {
    title: "Name",
    dataIndex: "name",
    width: 210
  },
  {
    title: "Description",
    dataIndex: "description"
  }
];

class ReportOverview extends Component {
  constructor(props) {
    super(props);

    const r = this.props.report;

    this.overview = [
      {
        key: "Filename",
        value: r.file_name
      },
      {
        key: "Type",
        value: r.type
      },
      {
        key: "Execution time (s)",
        value: r.exec_time
      },
      {
        key: "Analysis time",
        value: r.timestamp
      },
      {
        key: "MD5",
        value: r.md5
      },
      {
        key: "SHA1",
        value: r.sha1
      },
      {
        key: "SHA256",
        value: r.sha256
      },
      {
        key: "Architecture",
        value: r.static_analysis.binary_info.arch
      },
      {
        key: "Endianess",
        value: r.static_analysis.binary_info.endianess
      }
    ];

    let anomalies = r.network_analysis.anomalies;
    this.anomalies = [];
    for (let i = 0; i < anomalies.length; i++) {
      this.anomalies.push({
        key: i,
        name: anomalies[i].name,
        description: anomalies[i].description,
        data: JSON.stringify(anomalies[i].data, null, 4)
      });
    }
  }

  downloadReport = () => {
    window.open(
      "http://" + process.env.REACT_APP_HOST + "/api/json/" + this.props.id
    );
  };

  downloadPcap = () => {
    window.open(
      "http://" + process.env.REACT_APP_HOST + "/api/pcap/" + this.props.id
    );
  };

  downloadProgramOutput = () => {
    window.open(
      "http://" + process.env.REACT_APP_HOST + "/api/output/" + this.props.id
    );
  };

  downloadMachineLog = () => {
    window.open(
      "http://" +
        process.env.REACT_APP_HOST +
        "/api/machinelog/" +
        this.props.id
    );
  };

  anomalyDataRenderer = anomaly => {
    return <code className="code-data">{anomaly.data}</code>;
  };

  render() {
    let pagination = { pageSize: 10, size: "small" };

    return (
      <div id="report-overview">
        <h3 className="report-section-headline">File overview</h3>

        <Table
          columns={columnsOverview}
          dataSource={this.overview}
          pagination={false}
          showHeader={false}
          className="table-no-pagination"
        />

        <h3 className="report-section-headline">Downloads</h3>
        <div className="downloads-section">
          <Button type="default" icon="download" onClick={this.downloadReport}>
            Report
          </Button>

          <Button type="default" icon="download" onClick={this.downloadPcap}>
            Pcap
          </Button>

          <Button
            type="default"
            icon="download"
            onClick={this.downloadProgramOutput}
          >
            Program output
          </Button>

          <Button
            type="default"
            icon="download"
            onClick={this.downloadMachineLog}
          >
            Machine log
          </Button>
        </div>

        <h3 className="report-section-headline">Anomalies</h3>

        <Table
          columns={columnsAnomalies}
          dataSource={this.anomalies}
          pagination={pagination}
          expandedRowRender={this.anomalyDataRenderer}
        />
      </div>
    );
  }
}

export default ReportOverview;
