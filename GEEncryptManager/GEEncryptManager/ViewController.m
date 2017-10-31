//
//  ViewController.m
//  GEEncryptManager
//
//  Created by goldeneye on 2017/10/30.
//  Copyright © 2017年 goldeneye by smart-small. All rights reserved.
//

#import "ViewController.h"
#import "GEEncrytDetailViewController.h"

static NSString * const cellIdtentifier = @"cell";

@interface ViewController ()<UITableViewDelegate,UITableViewDataSource>

@property(nonatomic,strong)UITableView * tableV;
@property(nonatomic,strong)NSArray * dataArr;

@end

@implementation ViewController
- (UITableView *)tableV
{
    if (!_tableV) {
        _tableV = [[UITableView alloc]initWithFrame:self.view.bounds style:UITableViewStylePlain];
        _tableV.delegate = self;
        _tableV.dataSource = self;
        //_tableV.separatorStyle = 0;
        [_tableV registerClass:[UITableViewCell class] forCellReuseIdentifier:cellIdtentifier];
    }
    return _tableV;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.dataArr = @[@"md5加密",@"SHA1加密",@"SHA224加密",@"SHA256加密",@"SHA384加密",@"SHA512加密",@"HmacSha1加密",@"HmacSha224加密",@"HmacSha256加密",@"HmacSha384加密",@"HmacSha512加密",@"HmacMD5加密",@"DES加/解密",@"AES加/解密",@"RSA公钥key加密、私钥key解密",@"RSA公钥.der文件加密、私钥.p12文件解密"];
    [self.view addSubview:self.tableV];

    // Do any additional setup after loading the view, typically from a nib.
}

#pragma UITableViewDelegate UITableViewDataSource

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView{
    
    return 1;
}
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return self.dataArr.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell * cell = [tableView dequeueReusableCellWithIdentifier:cellIdtentifier forIndexPath:indexPath];
    
    if (!cell) {
        cell = [[UITableViewCell alloc]initWithStyle:UITableViewCellStyleDefault reuseIdentifier:cellIdtentifier];
    }
    cell.textLabel.text = self.dataArr[indexPath.row];
    return cell;
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    
    GEEncrytDetailViewController *detail = [[GEEncrytDetailViewController alloc] init];
    detail.showString = self.dataArr[indexPath.row];

    [self.navigationController pushViewController:detail animated:YES];
}
- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
