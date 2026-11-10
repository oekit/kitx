package auth

import (
	"errors"
	"fmt"

	bizerrors "github.com/oekit/pkg/errors"
)

// ErrUnauthorized 是 401 语义总集（BizError 401——middleware.Fail 自动映射
// HTTP 401）：凭据无效、令牌已吊销、会话不在、查无此人，统一从此外出（具体
// 缘由看外层 %w 文本，客户端响应不泄露区分——防用户枚举）。
//
// 与 500 的分型契约（#120 错误分型不变式）：本哨兵**只**承载「凭据不行」；
// 存储/仓储故障原样上抛（非 BizError，handler 层归 500）——数据面故障既不
// 放行也不放大成 401。
var ErrUnauthorized = bizerrors.NewUnauthorizedError("凭据无效")

// ErrReplayed 是 refresh 重放哨兵（#120：旧 refresh 二次使用）：被轮换换出、
// 被强踢、被登出的 refresh 再次出现即此错。链上同时含 ErrUnauthorized
// （errors.Is 双判），下游可按需分流「重放 → 告警」而不影响 401 映射。
var ErrReplayed = fmt.Errorf("%w: refresh 重放（旧令牌二次使用）", ErrUnauthorized)

// ErrUserNotFound 是 UserRepo.GetByID 的契约哨兵（查无此人）。Flow 把它归
// 401（不泄露存在性）；仓储适配器必须把「查无此人」映射到本哨兵，其余错误
// （DB 故障等）原样上抛（归 500）——两者混同会让排障无法分型。
var ErrUserNotFound = errors.New("auth: 用户不存在")
