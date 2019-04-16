import React, { Component } from "react";
import { Icon, List, Table } from "antd";
import Flag from "react-world-flags";

import { countryCodes } from "../data/countryCodes";

const columnsHTTP = [
  {
    title: "Method",
    dataIndex: "method",
    width: 160
  },
  {
    title: "URI",
    dataIndex: "uri"
  }
];

const columnsDNS = [
  {
    title: "Name",
    dataIndex: "name"
  },
  {
    title: "Type",
    dataIndex: "type",
    width: 200
  }
];

const columnsEndpoints = [
  {
    title: "IP",
    dataIndex: "ip"
  },
  {
    title: "Data In",
    dataIndex: "data_in",
    width: 150
  },
  {
    title: "Data Out",
    dataIndex: "data_out",
    width: 150
  },
  {
    title: "Country",
    width: 150,
    render: (text, record) => {
      if (!(record.country in countryCodes)) {
        return <span />;
      }
      let code = countryCodes[record.country];
      return (
        <div class="align-center">
          <Flag code={code} height="16" className="endpoint-flag" />
        </div>
      );
    }
  },
  {
    title: "Blacklist",
    width: 150,
    render: (text, record) => {
      if (record.blacklisted) {
        return <Icon type="warning" className="endpoint-blacklisted" />;
      }
      return <span />;
    }
  }
];

class ReportNetwork extends Component {
  constructor(props) {
    super(props);

    const r = this.props.report;

    this.httpRequests = [];
    for (let i = 0; i < r.http_requests.length; i++) {
      this.httpRequests.push({
        key: i,
        method: r.http_requests[i].method,
        uri: r.http_requests[i].uri,
        headers: r.http_requests[i].headers
      });
    }

    this.ircMessages = r.irc_messages;

    this.dnsQuestions = [];
    for (let i = 0; i < r.dns_questions.length; i++) {
      this.dnsQuestions.push({
        key: i,
        name: r.dns_questions[i].name,
        type: r.dns_questions[i].type
      });
    }

    this.endpoints = r.endpoints;

    this.telnetData = r.telnet_data;
  }

  httpDetailsRenderer = request => {
    let headers = request.headers;
    let data = [];
    let i = 0;
    for (let key in headers) {
      if (headers.hasOwnProperty(key)) {
        data.push(
          <p key={i}>
            <span className="key">{key}: </span>
            <span className="value">{headers[key]}</span>
          </p>
        );
        i++;
      }
    }
    return <div className="row-detail">{data}</div>;
  };

  endpointDetailsRenderer = endpoint => {
    let data = [];

    if (endpoint.hasOwnProperty("asn")) {
      if (endpoint.asn !== null) {
        data.push(
          <p key={0}>
            <span className="key">ASN: </span>
            <span className="value">{endpoint.asn}</span>
          </p>
        );
      }
    }

    if (endpoint.hasOwnProperty("country")) {
      if (endpoint.country !== null) {
        data.push(
          <p key={1}>
            <span className="key">Country: </span>
            <span className="value">{endpoint.country}</span>
          </p>
        );
      }
    }

    if (endpoint.hasOwnProperty("city")) {
      if (endpoint.city !== null) {
        data.push(
          <p key={2}>
            <span className="key">City: </span>
            <span className="value">{endpoint.city}</span>
          </p>
        );
      }
    }

    if (endpoint.hasOwnProperty("organization")) {
      if (endpoint.organization !== null) {
        data.push(
          <p key={3}>
            <span className="key">Organization: </span>
            <span className="value">{endpoint.organization}</span>
          </p>
        );
      }
    }

    data.push(
      <p key={4}>
        <span className="key">Accessed ports: </span>
        <span className="value">{endpoint.ports.join(", ")}</span>
      </p>
    );

    return <div className="row-detail">{data}</div>;
  };

  render() {
    let pagination = { pageSize: 5, size: "small" };

    let ircPagination = this.ircMessages.length === 0 ? false : pagination;

    return (
      <div className="report-part">
        <h3 className="report-section-headline">Endpoints</h3>

        <Table
          columns={columnsEndpoints}
          dataSource={this.endpoints}
          pagination={pagination}
          rowKey="ip"
          expandedRowRender={this.endpointDetailsRenderer}
        />

        <h3 className="report-section-headline">HTTP requests</h3>

        <Table
          columns={columnsHTTP}
          dataSource={this.httpRequests}
          pagination={pagination}
          expandedRowRender={this.httpDetailsRenderer}
        />

        <h3 className="report-section-headline">DNS questions</h3>

        <Table
          columns={columnsDNS}
          dataSource={this.dnsQuestions}
          pagination={pagination}
        />

        <h3 className="report-section-headline">Telnet data</h3>

        <List
          dataSource={this.telnetData}
          renderItem={item => <List.Item>{item}</List.Item>}
          pagination={pagination}
        />

        <h3 className="report-section-headline">IRC messages</h3>

        <List
          dataSource={this.ircMessages}
          renderItem={item => <List.Item>{item}</List.Item>}
          pagination={ircPagination}
        />
      </div>
    );
  }
}

export default ReportNetwork;
