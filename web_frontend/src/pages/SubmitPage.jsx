import React, { Component } from "react";
import { Button, Layout, Radio, Alert, Spin, InputNumber } from "antd";

const { Content, Header } = Layout;

class SubmitPage extends Component {
  constructor(props) {
    super(props);

    this.state = {
      file: "",
      type: "",
      exectime: 20,
      status: "",
      uploading: false,
      task_id: ""
    };
  }

  handleUpload = () => {
    this.setState({
      uploading: true,
      status: ""
    });

    let data = new FormData();

    if (this.state.type === "binary") {
      data.append("file", this.state.file);
      data.append("exec_time", this.state.exectime);

      fetch("http://" + process.env.REACT_APP_HOST + "/api/tasks/create/file", {
        method: "POST",
        body: data
      })
        .then(res => {
          let status = "";
          if (res.ok) {
            status = "success";
          } else {
            status = "error";
          }
          this.setState({
            status: status,
            file: ""
          });
          return res.json();
        })
        .then(obj => {
          this.setState({
            task_id: obj.task_id
          });
        })
        .catch(error => {
          console.log(error);
        });
    }

    if (this.state.type === "pcap") {
      data.append("pcap", this.state.file);

      fetch("http://" + process.env.REACT_APP_HOST + "/api/tasks/create/pcap", {
        method: "POST",
        body: data
      })
        .then(res => {
          let status = "";
          if (res.ok) {
            status = "success";
          } else {
            status = "error";
          }
          this.setState({
            status: status,
            file: ""
          });
          return res.json();
        })
        .then(obj => {
          this.setState({
            task_id: obj.task_id
          });
        })
        .catch(error => {
          console.log(error);
        });
    }
  };

  handleInput = event => {
    this.setState({
      file: event.target.files[0]
    });
  };

  handleSelectRadio = event => {
    this.setState({
      type: event.target.value
    });
  };

  handleInputExecutionTime = value => {
    this.setState({
      exectime: value
    });
  };

  render() {
    const { file, type, status, uploading, task_id } = this.state;

    let disabled = true;
    let alert;

    if (file !== "" && type !== "") {
      disabled = false;
    }

    if (status === "success") {
      alert = (
        <Alert
          message="Success"
          description={
            "File was sucessfuly uploaded. Your task_id is " + task_id
          }
          type="success"
          showIcon
        />
      );
    } else if (status === "error") {
      alert = (
        <Alert
          message="Error"
          description="Error uploading file."
          type="error"
          showIcon
        />
      );
    } else {
      if (uploading) {
        alert = (
          <div className="align-center">
            <Spin size="large" />
          </div>
        );
      }
    }

    let binaryForm;

    if (type === "pcap") {
      binaryForm = <div />;
    } else {
      binaryForm = (
        <div className="upload-form-row">
          <p className="upload-form-label">
            <label title="Execution time">Execution time (seconds)</label>
          </p>
          <div className="upload-form-input">
            <InputNumber
              className="upload-form-exectime-input"
              min={10}
              max={1000}
              defaultValue={20}
              onChange={this.handleInputExecutionTime}
            />
          </div>
        </div>
      );
    }

    return (
      <Layout style={{ marginLeft: 200 }}>
        <Header className="header">
          <h2 className="header-headline">Submit file</h2>
        </Header>
        <Content className="page-content">
          <div className="inner-page-content">
            <div className="upload-form">
              <div className="upload-form-row">
                <p className="upload-form-label">
                  <label title="Analysis type">Analysis type</label>
                </p>
                <div className="upload-form-input">
                  <Radio.Group onChange={this.handleSelectRadio}>
                    <Radio.Button value="binary">binary</Radio.Button>
                    <Radio.Button value="pcap">pcap</Radio.Button>
                  </Radio.Group>
                </div>
              </div>

              <div className="upload-form-row">
                <p className="upload-form-label">
                  <label title="File">File</label>
                  <span className="upload-file-name">{file.name}</span>
                </p>
                <div className="upload-form-input">
                  <label className="upload-file-input ant-btn ant-btn-default">
                    <input
                      type="file"
                      className="hidden"
                      onChange={this.handleInput}
                    />
                    <span className="upload-label-text">Select file</span>
                  </label>
                </div>
              </div>

              {binaryForm}

              <div className="upload-form-row">
                <div className="upload-form-input">
                  <Button
                    type="primary"
                    icon="upload"
                    onClick={this.handleUpload}
                    disabled={disabled}
                    className="upload-submit"
                  >
                    Submit
                  </Button>
                </div>
              </div>
            </div>
            <div className="upload-alerts">{alert}</div>
          </div>
        </Content>
      </Layout>
    );
  }
}

export default SubmitPage;
