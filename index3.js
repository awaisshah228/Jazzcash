const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
app.use(express.json());

app.post('/createCharge', (req, res) => {
  const jazzcash = new JazzcashApi();
  const response = jazzcash.createCharge(req.body);
  res.json(response);
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});

class JazzcashApi {
  constructor() {
    this.merchant_id = process.env.JAZZCASH_MERCHANT_ID;
    this.password = process.env.JAZZCASH_PASSWORD;
    this.integrity_salt = process.env.JAZZCASH_INTEGERITY_SALT;
    this.currency = process.env.JAZZCASH_CURRENCY_CODE;
    this.language = process.env.JAZZCASH_LANGUAGE;
    this.post_url = process.env.JAZZCASH_HTTP_POST_URL;
  }

  createCharge(form_data) {
    const pp_TxnDateTime = new Date().toISOString().replace(/[-:.TZ]/g, '');
    const pp_TxnExpiryDateTime = new Date(
      Date.now() + 1 * 60 * 60 * 1000
    ).toISOString().replace(/[-:.TZ]/g, '');
    const pp_TxnRefNo = 'T' + pp_TxnDateTime;
    const pp_Amount = Math.round(form_data.price * 100);

    const additional_data = {
      pp_TxnDateTime,
      pp_TxnExpiryDateTime,
      pp_TxnRefNo,
      pp_Amount,
    };

    let data_array;
    if (form_data.paymentMethod === 'jazzcashMobile') {
      this.post_url = process.env.JAZZCASH_HTTP_POST_URL;
      data_array = this.get_mobile_payment_array(form_data, additional_data);
    } else if (form_data.paymentMethod === 'jazzcashCard') {
      this.post_url = process.env.JAZZCASH_CARD_API_URL;
      data_array = this.get_card_payment_array(form_data, additional_data);
    } else {
      throw new Error('Please select a valid payment method and try again');
    }

    const pp_SecureHash = this.get_SecureHash(data_array);
    data_array.pp_SecureHash = pp_SecureHash;

    return this.callAPI(data_array);
  }

  get_SecureHash(data_array) {
    const sortedKeys = Object.keys(data_array).sort();
    const str = sortedKeys
      .map((key) => data_array[key])
      .filter((value) => value !== '')
      .join('&');

    const hash = crypto.createHmac('sha256', this.integrity_salt)
      .update(this.integrity_salt + str)
      .digest('hex');

    return hash;
  }

  async callAPI(data) {
    try {
      const response = await axios.post(this.post_url, data, {
        headers: { 'Content-Type': 'application/json' },
      });
      return response.data;
    } catch (error) {
      throw new Error('Connection Failure');
    }
  }

  get_mobile_payment_array(form_data, additional_data) {
    const data = {
      pp_Language: this.language,
      pp_MerchantID: this.merchant_id,
      pp_SubMerchantID: '',
      pp_Password: this.password,
      pp_BankID: '',
      pp_ProductID: '',
      pp_TxnRefNo: additional_data.pp_TxnRefNo,
      pp_Amount: additional_data.pp_Amount,
      pp_TxnCurrency: this.currency,
      pp_TxnDateTime: additional_data.pp_TxnDateTime,
      pp_BillReference: 'billRef',
      pp_Description: 'Description',
      pp_TxnExpiryDateTime: additional_data.pp_TxnExpiryDateTime,
      pp_SecureHash: '',
      ppmpf_1: '',
      ppmpf_2: '',
      ppmpf_3: '',
      ppmpf_4: '',
      ppmpf_5: '',
      pp_MobileNumber: form_data.jazz_cash_no,
      pp_CNIC: form_data.cnic_digits,
    };

    return data;
  }

  get_card_payment_array(form_data, additional_data) {
    const data = {
      pp_IsRegisteredCustomer: 'No',
      pp_ShouldTokenizeCardNumber: 'No',
      pp_CustomerID: 'test',
      pp_CustomerEmail: 'test@test.com',
      pp_CustomerMobile: '03222852628',
      pp_TxnType: 'MPAY',
      pp_TxnRefNo: additional_data.pp_TxnRefNo,
      pp_MerchantID: this.merchant_id,
      pp_Password: this.password,
      pp_Amount: additional_data.pp_Amount,
      pp_TxnCurrency: this.currency,
      pp_TxnDateTime: additional_data.pp_TxnDateTime,
      pp_C3DSecureID: '',
      pp_TxnExpiryDateTime: additional_data.pp_TxnExpiryDateTime,
      pp_BillReference: 'billRef',
      pp_Description: 'Description of transaction',
      pp_CustomerCardNumber: form_data.ccNo,
      pp_CustomerCardExpiry: form_data.expMonth + form_data.expYear,
      pp_CustomerCardCvv: form_data.cvv,
    };

    return data;
  }
}
