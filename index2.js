const crypto = require('crypto');
const axios = require('axios');
const express = require('express');

class Jazzcash {
  constructor() {
    this._cred = {};
    this._prefix = 'JC_';
    this._hash = 'SHA256';
    this._data = {};
    this._ver = '1.1';
    this.purl = '/ApplicationAPI/API/';
    this._isToken = false;
    this.sandbox = true;
    this.reqType = 'Authorize';
    this.hashF = [];

    this.initCredentials();
  }

  initCredentials() {
    if (
      !process.env[this._prefix + 'SALT'] ||
      !process.env[this._prefix + 'PASS'] ||
      !process.env[this._prefix + 'MERCHANT_ID']
    ) {
      throw new Error('JazzCash configuration missing');
    }

    this._cred.salt = process.env[this._prefix + 'SALT'];
    this._cred.pass = process.env[this._prefix + 'PASS'];
    this._cred.mch = process.env[this._prefix + 'MERCHANT_ID'];
  }

  ver() {
    if (this._ver >= 2) {
      return this.purl + this._ver + '/';
    }
    return this.purl;
  }

  actionURL() {
    let endpoint = '';
    switch (this.reqType.toUpperCase()) {
      case 'PAY':
        endpoint = 'Purchase/PAY';
        this.hashF = [
          'pp_CustomerCardNumber',
          'pp_CustomerCardExpiry',
          'pp_CustomerCardCvv',
          'pp_Amount',
          'pp_TxnRefNo',
          'pp_MerchantID',
          'pp_Password',
          'pp_TxnCurrency',
          'pp_Frequency',
          'pp_InstrumentType',
        ];
        break;
      case 'CHECK3DSENROLLMENT':
        endpoint = this.ver() + 'Purchase/Check3DsEnrollment';
        this.hashF = [
          'pp_CustomerCardNumber',
          'pp_CustomerCardExpiry',
          'pp_CustomerCardCvv',
          'pp_Amount',
          'pp_TxnRefNo',
          'pp_MerchantID',
          'pp_Password',
          'pp_TxnCurrency',
          'pp_Frequency',
          'pp_InstrumentType',
        ];
        break;
      case 'AUTHORIZE':
        endpoint = this.ver() + 'authorize/AuthorizePayment';
        this.hashF = [
          'pp_CustomerCardNumber',
          'pp_CustomerCardExpiry',
          'pp_CustomerCardCvv',
          'pp_Amount',
          'pp_TxnRefNo',
          'pp_MerchantID',
          'pp_Password',
          'pp_TxnCurrency',
          'pp_Frequency',
          'pp_InstrumentType',
        ];
        break;
      case 'CAPTURE':
        endpoint = this.ver() + 'authorize/Capture';
        this.hashF = [
          'pp_CustomerCardNumber',
          'pp_CustomerCardExpiry',
          'pp_CustomerCardCvv',
          'pp_Amount',
          'pp_TxnRefNo',
          'pp_MerchantID',
          'pp_Password',
          'pp_TxnCurrency',
          'pp_Frequency',
          'pp_InstrumentType',
        ];
        break;
      case 'REFUND':
        endpoint = this.ver() + 'authorize/Refund';
        this.hashF = [
          'pp_CustomerCardNumber',
          'pp_CustomerCardExpiry',
          'pp_CustomerCardCvv',
          'pp_Amount',
          'pp_TxnRefNo',
          'pp_MerchantID',
          'pp_Password',
          'pp_TxnCurrency',
          'pp_Frequency',
          'pp_InstrumentType',
        ];
        break;
      case 'VOID':
        endpoint = this.ver() + 'authorize/Void';
        this.hashF = ['pp_TxnRefNo', 'pp_MerchantID', 'pp_Password'];
        break;
      case 'PAYMENTINQUIRY':
        endpoint = this.ver() + 'PaymentInquiry/Inquire';
        this.hashF = ['pp_TxnRefNo', 'pp_MerchantID', 'pp_Password', 'pp_Version'];
        break;
    }

    if (this._isToken) {
      return endpoint + 'ViaToken';
    }
    return endpoint;
  }

  url() {
    const url = process.env[this._prefix + (this.sandbox === false ? 'LIVE' : 'SANDBOX') + '_URL'];
    return url + this.actionURL();
  }

  set_data(attr, val = '') {
    if (typeof attr === 'object') {
      Object.assign(this._data, attr);
    } else {
      this._data[attr] = val;
    }
  }

  get_data(attr) {
    if (attr) {
      return this._data[attr] || null;
    }
    return this._data;
  }

  genString(i, array, res = '') {
    if (Array.isArray(array)) {
      for (const key in array) {
        if (Array.isArray(array[key])) {
          res = this.genString(i, array[key], res);
        } else if (key === i && array[key]) {
          res = array[key] + '&';
        }
      }
    }
    return res;
  }

  secureHash() {
    this.actionURL();
    this.hashF.sort();

    let f = '';
    for (const h of this.hashF) {
      f += this.genString(h, this.get_data());
    }

    const a = this._cred.salt + '&';
    const b = a + f.slice(0, -1);
    const hash = crypto.createHmac(this._hash, this._cred.salt).update(b).digest('hex');
    return hash;
  }

  loadDefaultAttr() {
    this.set_data({
      pp_TxnCurrency: 'PKR',
      pp_MerchantID: this._cred.mch,
      pp_Password: this._cred.pass,
    });

    if (this.reqType.toUpperCase() === 'PAY') {
      this.set_data({
        pp_TxnType: 'MPAY',
        pp_Version: this._ver,
      });
    }

    this.set_data('pp_SecureHash', this.secureHash());

    if (this._ver < 2 && !['PAY', 'PAYMENTINQUIRY'].includes(this.reqType.toUpperCase())) {
      const a = {};
      a[this.reqType + 'Request'] = this.get_data();
      this._data = a;
    }
  }

  validatePayload() {
    if (!this.get_data('pp_TxnRefNo')) {
      throw new Error('Transaction reference number is required');
    } else if (!this.get_data('pp_Amount')) {
      throw new Error('Amount is missing');
    } else if (
      !this.get_data('InstrumentDTO') ||
      !this.get_data('InstrumentDTO').pp_CustomerCardNumber ||
      !this.get_data('InstrumentDTO').pp_CustomerCardExpiry ||
      !this.get_data('InstrumentDTO').pp_CustomerCardCvv
    ) {
      throw new Error('Card details missing');
    }

    return true;
  }

  send() {
    if (!crypto.createHash) {
      throw new Error('Please enable crypto module');
    }

    this.loadDefaultAttr();
    this.validatePayload();

    const data = JSON.stringify(this.get_data());

    const options = {
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length,
      },
    };

    return axios
      .post(this.url(), data, options)
      .then((response) => response.data)
      .catch((error) => {
        throw new Error(error.message);
      });
  }
}

// Example Express usage
const app = express();
app.use(express.json());

app.post('/pay', (req, res) => {
  const jazzcash = new Jazzcash();
  jazzcash.reqType = 'PAY';
  jazzcash.set_data(req.body);

  jazzcash
    .send()
    .then((response) => {
      res.json(response);
    })
    .catch((error) => {
      res.status(500).json({ error: error.message });
    });
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
