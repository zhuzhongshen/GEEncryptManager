//
//  GEEncrytDetailViewController.m
//  GEEncryptManager
//
//  Created by goldeneye on 2017/10/30.
//  Copyright © 2017年 goldeneye by smart-small. All rights reserved.
//

#import "GEEncrytDetailViewController.h"


@interface GEEncrytDetailViewController ()<UITextFieldDelegate>
@property (nonatomic,strong)UITextField *inputTextFiled;
@property(nonatomic,strong)UIButton * encrytBtn , * decryptBtn;
@property(nonatomic,strong)UITextView * encryTextView;
@property (nonatomic,strong)UITextView *unencryTextView;

@end

@implementation GEEncrytDetailViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.view.backgroundColor = [UIColor whiteColor];
    
    self.navigationItem.title = self.showString;
    [self.view addSubview:self.inputTextFiled];
    [self.view addSubview:self.encryTextView];
    [self.view addSubview:self.unencryTextView];
    
    [self.view addSubview:self.encrytBtn];
    
   [self.view addSubview:self.decryptBtn];
    
    
    // Do any additional setup after loading the view from its nib.
}


- (UITextField *)inputTextFiled
{
    if (!_inputTextFiled) {
        _inputTextFiled = [[UITextField alloc]initWithFrame:CGRectMake(20, 100, 250, 40)];
        _inputTextFiled.borderStyle =  UITextBorderStyleRoundedRect;
        _inputTextFiled.delegate = self;
        
    }
    return _inputTextFiled;
}
- (BOOL)textFieldShouldReturn:(UITextField *)textField
{
    [self.view endEditing:YES];
    return NO;
}
- (UITextView *)encryTextView
{
    if (!_encryTextView) {
        _encryTextView = [[UITextView alloc]initWithFrame:CGRectMake(20, 160, 250, 80)];
        _encryTextView.backgroundColor = [UIColor lightGrayColor];
        _encryTextView.userInteractionEnabled = NO;
    }
    return _encryTextView;
}
- (UITextView *)unencryTextView
{
    if (!_unencryTextView) {
        _unencryTextView = [[UITextView alloc]initWithFrame:CGRectMake(20, 260, 250, 80)];
        _unencryTextView.backgroundColor = [UIColor lightGrayColor];
        _unencryTextView.userInteractionEnabled = NO;
    }
    return _unencryTextView;
}
- (UIButton *)encrytBtn
{
    if (!_encrytBtn) {
        _encrytBtn = [UIButton buttonWithType:UIButtonTypeCustom];
        [_encrytBtn setFrame:CGRectMake(20, self.view.bounds.size.height-44-20, 80, 44)];
        [_encrytBtn setTitle:@"加密" forState:UIControlStateNormal];
        [_encrytBtn addTarget:self action:@selector(encrytClick:) forControlEvents:UIControlEventTouchUpInside];
        _encrytBtn.backgroundColor = [UIColor redColor];
        
        
    }
    return _encrytBtn;
}
- (UIButton *)decryptBtn
{
    if (!_decryptBtn) {
        _decryptBtn = [UIButton buttonWithType:UIButtonTypeCustom];
        [_decryptBtn setFrame:CGRectMake(self.view.bounds.size.width-80-20, self.view.bounds.size.height-44-20, 80, 44)];
        [_decryptBtn setTitle:@"解密" forState:UIControlStateNormal];
        [_decryptBtn addTarget:self action:@selector(decryptClick:) forControlEvents:UIControlEventTouchUpInside];
        _decryptBtn.backgroundColor = [UIColor redColor];
        
        
    }
    return _decryptBtn;
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

/*
 #pragma mark - Navigation
 
 // In a storyboard-based application, you will often want to do a little preparation before navigation
 - (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
 // Get the new view controller using [segue destinationViewController].
 // Pass the selected object to the new view controller.
 }
 */
///*加密*/
- (void)encrytClick:(id)sender {
    
    if ([self.showString isEqualToString:@"md5加密"]) {
        //md5加密
        self.encryTextView.text = [GEEncryptManager ge_md5EncrypWithString:self.inputTextFiled.text];
        NSLog(@"%@====",[GEEncryptManager ge_md5EncrypWithString:self.inputTextFiled.text]);
    }else if ([self.showString isEqualToString:@"SHA1加密"]){
        //self.encryTextView.text = [GEEncryptManager ge_sha1EncrytWithString:self.inputTextFiled.text];
        self.encryTextView.text = [GEEncryptManager ge_SHAWithType:GEEncrytShaTypeSha1 encryptWithString:self.inputTextFiled.text];
        
    }else if ([self.showString isEqualToString:@"SHA224加密"]){
        //        self.encryTextView.text = [GEEncryptManager ge_sha224EncrytWithString:self.inputTextFiled.text];
        self.encryTextView.text = [GEEncryptManager ge_SHAWithType:GEEncrytShaTypeSha224 encryptWithString:self.inputTextFiled.text];
    }else if ([self.showString isEqualToString:@"SHA256加密"]){
        //  self.encryTextView.text = [GEEncryptManager ge_sha256EncrytWithString:self.inputTextFiled.text];
        self.encryTextView.text = [GEEncryptManager ge_SHAWithType:GEEncrytShaTypeSha256 encryptWithString:self.inputTextFiled.text];
    }else if ([self.showString isEqualToString:@"SHA384加密"]){
        //self.encryTextView.text = [GEEncryptManager ge_sha384EncrytWithString:self.inputTextFiled.text];
        self.encryTextView.text = [GEEncryptManager ge_SHAWithType:GEEncrytShaTypeSha384 encryptWithString:self.inputTextFiled.text];
    }else if ([self.showString isEqualToString:@"SHA512加密"]){
        //self.encryTextView.text = [GEEncryptManager ge_sha512EncrytWithString:self.inputTextFiled.text];
        self.encryTextView.text = [GEEncryptManager ge_SHAWithType:GEEncrytShaTypeSha512 encryptWithString:self.inputTextFiled.text];
    }else if ([self.showString isEqualToString:@"HmacSha1加密"])
    {
        self.encryTextView.text = [GEEncryptManager ge_HmacShaWithType:GEEncrytHmacTypeSha1 encryptWithString:self.inputTextFiled.text withKey:encrytKey];
    }else if ([self.showString isEqualToString:@"HmacSha224加密"])
    {
            self.encryTextView.text = [GEEncryptManager ge_HmacShaWithType:GEEncrytHmacTypeSha224 encryptWithString:self.inputTextFiled.text withKey:encrytKey];
//        self.encryTextView.text = [GEEncryptManager ge_HmacSha224EncrytWithString:self.inputTextFiled.text withKey:encrytKey];
    }
    else if ([self.showString isEqualToString:@"HmacSha256加密"])
    {
        self.encryTextView.text = [GEEncryptManager ge_HmacShaWithType:GEEncrytHmacTypeSha256 encryptWithString:self.inputTextFiled.text withKey:encrytKey];
    }
    else if ([self.showString isEqualToString:@"HmacSha384加密"])
    {
        self.encryTextView.text = [GEEncryptManager ge_HmacShaWithType:GEEncrytHmacTypeSha384 encryptWithString:self.inputTextFiled.text withKey:encrytKey];
    }else if ([self.showString isEqualToString:@"HmacSha512加密"])
    {
        self.encryTextView.text = [GEEncryptManager ge_HmacShaWithType:GEEncrytHmacTypeSha512 encryptWithString:self.inputTextFiled.text withKey:encrytKey];
    }else if ([self.showString isEqualToString:@"HmacMD5加密"])
    {
        self.encryTextView.text = [GEEncryptManager ge_HmacShaWithType:GEEncrytHmacTypeShaMD5 encryptWithString:self.inputTextFiled.text withKey:encrytKey];
    }else if ([self.showString isEqualToString:@"DES加/解密"])
    {
        self.encryTextView.text = [GEEncryptManager ge_DESEncryptWithString:self.inputTextFiled.text withKey:encrytKey];
    }else if ([self.showString isEqualToString:@"AES加/解密"])
    {
        self.encryTextView.text = [GEEncryptManager ge_AESEncryptWithString:self.inputTextFiled.text witkPassword:encrytKey];
    }else if ([self.showString isEqualToString:@"RSA公钥key加密、私钥key解密"]){
        
        self.encryTextView.text = [GEEncryptManager ge_RSAEncryptWithString:self.inputTextFiled.text withPublicKey:RSA_PublicKey];
    }else if([self.showString isEqualToString:@"RSA公钥.der文件加密、私钥.p12文件解密"]){
        
        self.encryTextView.text = [GEEncryptManager ge_RSAEncryptWithString:self.inputTextFiled.text publicKeyWithContentOfFileName:@"public_key"];
        
    }
    
}
//
/*解密*/
- (void)decryptClick:(id)sender {

    if ([self.showString isEqualToString:@"RSA公钥key加密、私钥key解密"]) {
      
      self.unencryTextView.text = [GEEncryptManager ge_RSADecryptWithString:self.encryTextView.text withPrivateKey:RSA_PrivateKey];
    }else if([self.showString isEqualToString:@"RSA公钥.der文件加密、私钥.p12文件解密"]){
        self.unencryTextView.text = [GEEncryptManager ge_RSADecryptWithString:self.encryTextView.text privateKeyWithContentsOfFileName:@"private_key" password:@"987654321"];
        
    }else if ([self.showString isEqualToString:@"DES加/解密"])
    {

        self.unencryTextView.text = [GEEncryptManager ge_DESDecryptWithString:self.encryTextView.text withKey:encrytKey];
    }else if ([self.showString isEqualToString:@"AES加/解密"])
    {
         self.unencryTextView.text = [GEEncryptManager ge_AESDecryptWithString:self.encryTextView.text witkPassword:encrytKey];
        
    }
}
@end
