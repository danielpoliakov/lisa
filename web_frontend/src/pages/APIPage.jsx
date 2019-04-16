import React, { Component } from "react";
import { Layout, Collapse } from "antd";

const { Content, Header } = Layout;
const Panel = Collapse.Panel;

const APIDataReturn = {
  taskID: {
    task_id: "8fd49755-fe4b-4ca1-b1a1-046676475d33"
  },
  allTasks: [
    {
      date_done: "Wed, 10 Apr 2019 09:58:27 GMT",
      status: "SUCCESS",
      task_id: "8fd49755-fe4b-4ca1-b1a1-046676475d33",
      result: "... (see finished x failed tasks for result specification)"
    }
  ],
  finishedTasks: [
    {
      date_done: "Wed, 10 Apr 2019 09:58:27 GMT",
      status: "SUCCESS",
      task_id: "8fd49755-fe4b-4ca1-b1a1-046676475d33",
      result: {
        filename: "malware.bin"
      }
    }
  ],
  failedTasks: [
    {
      date_done: "Wed, 10 Apr 2019 09:58:27 GMT",
      status: "SUCCESS",
      task_id: "8fd49755-fe4b-4ca1-b1a1-046676475d33",
      result: {
        exc_type: "ValueError",
        filename: "malware.bin",
        traceback: "Traceback (most recent call last): ..."
      }
    }
  ],
  pendingTasks: {
    "lisa-worker@e1c9644fdd8d": [
      {
        acknowledged: false,
        args:
          "('/home/lisa/data/storage/8fd49755-fe4b-4ca1-b1a1-046676475d33/malware.bin',)",
        hostname: "lisa-worker@e1c9644fdd8d",
        id: "8fd49755-fe4b-4ca1-b1a1-046676475d33",
        kwargs: "{'pretty': False}",
        name: "lisa.web_api.tasks.full_analysis"
      }
    ]
  },
  taskStatus: {
    status: "SUCCESS"
  }
};

const docsData = [
  {
    header: (
      <div className="api-docs-header">
        <span className="api-tag api-tag-post">POST</span>
        <code>/api/tasks/create/file</code>
        <p className="api-short-desc">Creates full binary analysis task.</p>
      </div>
    ),
    inner: (
      <div className="api-docs-inner">
        <h4>Parameters</h4>
        <ul>
          <li>
            <code className="api-param">file</code> File for analysis.
          </li>
          <li>
            <code className="api-param">pretty</code> JSON indentation
            <code> (true|false)</code> - optional.
          </li>
        </ul>

        <h4>Returns</h4>

        <code className="api-code-block">
          {JSON.stringify(APIDataReturn.taskID, null, 2)}
        </code>
      </div>
    )
  },
  {
    header: (
      <div className="api-docs-header">
        <span className="api-tag api-tag-post">POST</span>
        <code>/api/tasks/create/pcap</code>
        <p className="api-short-desc">Creates pcap analysis task.</p>
      </div>
    ),
    inner: (
      <div className="api-docs-inner">
        <h4>Parameters</h4>

        <ul>
          <li>
            <code className="api-param">pcap</code> Pcap for analysis.
          </li>
          <li>
            <code className="api-param">pretty</code> JSON indentation
            <code> (true|false)</code> - optional.
          </li>
        </ul>

        <h4>Returns</h4>

        <code className="api-code-block">
          {JSON.stringify(APIDataReturn.taskID, null, 2)}
        </code>
      </div>
    )
  },
  {
    header: (
      <div className="api-docs-header">
        <span className="api-tag api-tag-get">GET</span>
        <code>/api/tasks</code>
        <p className="api-short-desc">Lists tasks.</p>
      </div>
    ),
    inner: (
      <div className="api-docs-inner">
        <h4>Parameters</h4>

        <ul>
          <li>
            <code className="api-param">limit</code> Maximum of returned items -
            optional.
          </li>
        </ul>

        <h4>Returns</h4>

        <code className="api-code-block">
          {JSON.stringify(APIDataReturn.allTasks, null, 2)}
        </code>
      </div>
    )
  },
  {
    header: (
      <div className="api-docs-header">
        <span className="api-tag api-tag-get">GET</span>
        <code>/api/tasks/finished</code>
        <p className="api-short-desc">Lists successfully finished tasks.</p>
      </div>
    ),
    inner: (
      <div className="api-docs-inner">
        <h4>Parameters</h4>

        <ul>
          <li>
            <code className="api-param">limit</code> Maximum of returned items -
            optional.
          </li>
        </ul>

        <h4>Returns</h4>

        <code className="api-code-block">
          {JSON.stringify(APIDataReturn.finishedTasks, null, 2)}
        </code>
      </div>
    )
  },
  {
    header: (
      <div className="api-docs-header">
        <span className="api-tag api-tag-get">GET</span>
        <code>/api/tasks/failed</code>
        <p className="api-short-desc">Lists failed tasks.</p>
      </div>
    ),
    inner: (
      <div className="api-docs-inner">
        <h4>Parameters</h4>

        <ul>
          <li>
            <code className="api-param">limit</code> Maximum of returned items -
            optional.
          </li>
        </ul>

        <h4>Returns</h4>

        <code className="api-code-block">
          {JSON.stringify(APIDataReturn.failedTasks, null, 2)}
        </code>
      </div>
    )
  },
  {
    header: (
      <div className="api-docs-header">
        <span className="api-tag api-tag-get">GET</span>
        <code>/api/tasks/pending</code>
        <p className="api-short-desc">Lists enqueued pending tasks.</p>
      </div>
    ),
    inner: (
      <div className="api-docs-inner">
        <h4>Parameters</h4>

        <ul>
          <li>
            <code className="api-param">limit</code> Maximum of returned items -
            optional.
          </li>
        </ul>

        <h4>Returns</h4>

        <code className="api-code-block">
          {JSON.stringify(APIDataReturn.pendingTasks, null, 2)}
        </code>
      </div>
    )
  },
  {
    header: (
      <div className="api-docs-header">
        <span className="api-tag api-tag-get">GET</span>
        <code>/api/tasks/view/&lt;task_id&gt;</code>
        <p className="api-short-desc">Returns tasks status.</p>
      </div>
    ),
    inner: (
      <div className="api-docs-inner">
        <h4>Returns</h4>

        <code className="api-code-block">
          {JSON.stringify(APIDataReturn.taskStatus, null, 2)}
        </code>
      </div>
    )
  },
  {
    header: (
      <div className="api-docs-header">
        <span className="api-tag api-tag-get">GET</span>
        <code>/api/report/&lt;task_id&gt;</code>
        <p className="api-short-desc">Returns analysis report.</p>
      </div>
    )
  },
  {
    header: (
      <div className="api-docs-header">
        <span className="api-tag api-tag-get">GET</span>
        <code>/api/pcap/&lt;task_id&gt;</code>
        <p className="api-short-desc">Returns pcap captured during analysis.</p>
      </div>
    )
  },
  {
    header: (
      <div className="api-docs-header">
        <span className="api-tag api-tag-get">GET</span>
        <code>/api/machinelog/&lt;task_id&gt;</code>
        <p className="api-short-desc">Returns QEMU machinelog.</p>
      </div>
    )
  },
  {
    header: (
      <div className="api-docs-header">
        <span className="api-tag api-tag-get">GET</span>
        <code>/api/output/&lt;task_id&gt;</code>
        <p className="api-short-desc">
          Returns analyzed program's stdout output.
        </p>
      </div>
    )
  }
];

class APIPage extends Component {
  render() {
    const panelsHTML = docsData.map((data, i) => {
      if (data.hasOwnProperty("inner")) {
        return (
          <Panel header={data.header} key={i}>
            {data.inner}
          </Panel>
        );
      }

      return <Panel header={data.header} key={i} showArrow={false} />;
    });

    return (
      <Layout style={{ marginLeft: 200 }}>
        <Header className="header">
          <h2 className="header-headline">API</h2>
        </Header>
        <Content className="page-content">
          <div className="inner-page-content">
            <h3 className="report-section-headline">Endpoints</h3>
            <Collapse bordered={false}>{panelsHTML}</Collapse>
          </div>
        </Content>
      </Layout>
    );
  }
}

export default APIPage;
